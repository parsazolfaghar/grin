"""Out-of-band interaction server for SSRF detection — grin's own collaborator.

The verifier injects a unique callback URL into a candidate param; if the TARGET makes a server-side
request to it, this listener records the hit and the verifier confirms SSRF. The precision comes from
two differential guards (adversarial-reviewed), not from "a unique token got hit":
  - HEALTH GATE: a startup self-test proves the listener is actually reachable; until it is, every
    SSRF verdict is INCONCLUSIVE (never REJECTED — a dead collaborator is a coverage gap, not a
    clean negative).
  - SOURCE-IP GUARD: the self-test also records grin's OWN source IP as seen by the listener; a
    callback from that IP is grin's client (e.g. it followed an open-redirect) and is excluded.
    Only a callback from a DIFFERENT source — the target making the request — confirms.

Scope: HTTP path-token callbacks (slice 1) AND DNS/hostname tokens (slice 2). The DNS arm catches
SSRF where HTTP egress is filtered but the target still RESOLVES an attacker hostname (blind SSRF /
hostname-allowlist bypass). Its precision guard is TOKEN UNIQUENESS, not a source-IP guard: grin
hands the unique <token>.<domain> hostname only to the target, so any query for it is target-side
resolution (with real delegation the query's source IP is the target's recursive resolver anyway).
Production use needs the OOB domain delegated to grin's authoritative server (the interactsh /
Collaborator model); the capture + verifier logic here is delegation-agnostic."""
from __future__ import annotations
import http.server
import socket
import struct
import threading
import time
import urllib.request
import uuid


def _parse_qname(data):
    """The QNAME of a DNS query (labels after the 12-byte header), lowercased. None on malformed."""
    try:
        i, labels = 12, []
        while True:
            ln = data[i]
            if ln == 0:
                break
            labels.append(data[i + 1:i + 1 + ln].decode("ascii", "replace"))
            i += 1 + ln
        return ".".join(labels).lower()
    except Exception:
        return None


def _dns_response(query, answer_ip):
    """A minimal A-record answer echoing the question and pointing at answer_ip (so the resolver gets
    a usable address — the belt-and-suspenders HTTP arm then reaches grin). Best-effort, single A."""
    try:
        i = 12
        while query[i] != 0:
            i += 1 + query[i]
        question = query[12:i + 1 + 4]                      # qname + qtype + qclass
        header = query[:2] + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
        answer = b"\xc0\x0c\x00\x01\x00\x01" + struct.pack(">I", 30) + b"\x00\x04" + socket.inet_aton(answer_ip)
        return header + question + answer
    except Exception:
        return None


class _DNSCapture:
    """A tiny UDP DNS server that records every query (QNAME + source) and answers A -> answer_ip."""
    def __init__(self, oob, port, bind_host, answer_ip):
        self.oob, self.port, self.bind_host, self.answer_ip = oob, port, bind_host, answer_ip
        self._sock = None
        self._stop = False

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.bind_host, self.port))
        self._sock.settimeout(0.5)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop:
            try:
                data, addr = self._sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break
            qname = _parse_qname(data)
            if qname:
                self.oob._record_dns(qname, addr[0])         # noqa: SLF001
            resp = _dns_response(data, self.answer_ip)
            if resp:
                try:
                    self._sock.sendto(resp, addr)
                except OSError:
                    pass

    def stop(self):
        self._stop = True
        if self._sock is not None:
            self._sock.close()


class _Handler(http.server.BaseHTTPRequestHandler):
    def _record(self):
        self.server.oob._record(self.path, self.client_address[0])   # noqa: SLF001
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = _record
    do_POST = _record

    def log_message(self, *args):
        pass


class OOBServer:
    def __init__(self, port, reachable_base, bind_host="0.0.0.0", dns_domain=None,
                 dns_port=53, dns_answer_ip=None):
        self.port = port
        self.bind_host = bind_host
        self.reachable_base = reachable_base.rstrip("/")
        self.dns_domain = (dns_domain or "").strip(".").lower() or None
        self.dns_port = dns_port
        # the A grin's DNS hands back: defaults to grin's own HTTP host (so the hostname's HTTP arm
        # also reaches grin) — falls back to 127.0.0.1 if the base host can't be parsed
        self.dns_answer_ip = dns_answer_ip or self._base_host() or "127.0.0.1"
        self._raw = []                 # (path, source_ip)
        self._dns_raw = []             # (qname, source_ip)
        self._lock = threading.Lock()
        self._grin_ips = set()
        self._healthy = False
        self._httpd = None
        self._dns = None

    def _base_host(self):
        from urllib.parse import urlparse
        try:
            return urlparse(self.reachable_base).hostname
        except Exception:
            return None

    def _record(self, path, ip):
        with self._lock:
            self._raw.append((path, ip))

    def _record_dns(self, qname, ip):
        with self._lock:
            self._dns_raw.append((qname, ip))

    def start(self):
        self._httpd = http.server.ThreadingHTTPServer((self.bind_host, self.port), _Handler)
        self._httpd.oob = self
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        if self.dns_domain:
            self._dns = _DNSCapture(self, self.dns_port, self.bind_host, self.dns_answer_ip)
            self._dns.start()

    def stop(self):
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._dns is not None:
            self._dns.stop()

    def mint_token(self):
        return "grinoob" + uuid.uuid4().hex[:16]

    def mint_dns_token(self):
        return "grindns" + uuid.uuid4().hex          # 128-bit, one per injection (FP guard)

    def dns_enabled(self):
        return bool(self.dns_domain)

    def dns_callback_host(self, token):
        return f"{token}.{self.dns_domain}"

    def dns_hit_sources(self, token):
        """Sources that queried a name containing the unique token. Uniqueness IS the guard: grin
        gave that hostname only to the target, so any query means target-side resolution."""
        with self._lock:
            return {ip for qname, ip in self._dns_raw if token in qname}

    def callback_url(self, token):
        return f"{self.reachable_base}/{token}"

    def hit_sources(self, token):
        with self._lock:
            return {ip for path, ip in self._raw if token in path}

    def grin_ips(self):
        return set(self._grin_ips)

    def healthy(self):
        return self._healthy

    def self_test(self, timeout=5):
        """Fetch our own callback to prove reachability AND learn grin's source IP as the listener
        sees it (so the verifier can exclude grin's own callbacks). Sets healthy on success."""
        token = self.mint_token()
        try:
            urllib.request.urlopen(self.callback_url(token), timeout=timeout)
        except Exception:
            pass
        deadline = time.time() + timeout
        while time.time() < deadline:
            srcs = self.hit_sources(token)
            if srcs:
                self._grin_ips |= srcs
                self._healthy = True
                return True
            time.sleep(0.1)
        return False
