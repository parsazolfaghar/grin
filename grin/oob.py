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

Scope (slice 1): HTTP path-token callbacks, synchronous poll. DNS/hostname tokens (for allowlist
bypass + delayed async exfil) and a deferred run-level finalize are documented follow-ups."""
from __future__ import annotations
import http.server
import threading
import time
import urllib.request
import uuid


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
    def __init__(self, port, reachable_base, bind_host="0.0.0.0"):
        self.port = port
        self.bind_host = bind_host
        self.reachable_base = reachable_base.rstrip("/")
        self._raw = []                 # (path, source_ip)
        self._lock = threading.Lock()
        self._grin_ips = set()
        self._healthy = False
        self._httpd = None

    def _record(self, path, ip):
        with self._lock:
            self._raw.append((path, ip))

    def start(self):
        self._httpd = http.server.ThreadingHTTPServer((self.bind_host, self.port), _Handler)
        self._httpd.oob = self
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()

    def stop(self):
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()

    def mint_token(self):
        return "grinoob" + uuid.uuid4().hex[:16]

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
