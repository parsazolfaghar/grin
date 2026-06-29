import urllib.parse
import urllib.request

from grin.oob import OOBServer
from grin.verify import verify, Candidate, Transport, CONFIRMED, REJECTED, INCONCLUSIVE


def _free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_oob_server_records_hits_and_self_test_health():
    port = _free_port()
    oob = OOBServer(port, f"http://127.0.0.1:{port}")
    oob.start()
    try:
        assert oob.self_test(timeout=5) is True and oob.healthy()
        tok = oob.mint_token()
        urllib.request.urlopen(oob.callback_url(tok), timeout=3)
        # the hit was recorded; grin's own source IP is known from the self-test
        import time
        for _ in range(20):
            if oob.hit_sources(tok):
                break
            time.sleep(0.1)
        assert oob.hit_sources(tok) and oob.grin_ips()
    finally:
        oob.stop()


# --- verifier oracle with a fake OOB (no real network) ---

class _FakeOOB:
    def __init__(self, healthy=True, dns_domain=None):
        self._healthy = healthy
        self._hits = {}
        self._dns_hits = {}
        self._dns_domain = dns_domain
        self._n = self._dn = 0

    def healthy(self):
        return self._healthy

    def mint_token(self):
        self._n += 1
        return f"tok{self._n}"

    def mint_dns_token(self):
        self._dn += 1
        return f"dtok{self._dn}"

    def callback_url(self, token):
        return f"http://oob.test/{token}"

    def dns_enabled(self):
        return bool(self._dns_domain)

    def dns_callback_host(self, token):
        return f"{token}.{self._dns_domain}"

    def grin_ips(self):
        return {"10.0.0.1"}

    def hit_sources(self, token):
        return self._hits.get(token, set())

    def dns_hit_sources(self, token):
        return self._dns_hits.get(token, set())

    def fire(self, token, ip):
        self._hits.setdefault(token, set()).add(ip)

    def fire_dns(self, token, ip):
        self._dns_hits.setdefault(token, set()).add(ip)


def _ssrf_candidate(oob):
    return Candidate(vuln_class="ssrf", location="/p (url)", url="http://t/p",
                     inject_field="url", oracle={"oob": oob, "ssrf_timeout": 2})


def test_verify_ssrf_confirmed_on_external_callback():
    oob = _FakeOOB()

    def request(method, url, json=None, headers=None):
        cb = (json or {}).get("url") if json else urllib.parse.unquote(url.split("url=", 1)[1])
        oob.fire(cb.rsplit("/", 1)[-1], "172.20.0.9")     # the TARGET fetches it (external IP)
        return (200, "ok")
    assert verify(_ssrf_candidate(oob), Transport(request=request)).status == CONFIRMED


def test_verify_ssrf_rejected_when_no_callback():
    oob = _FakeOOB()
    assert verify(_ssrf_candidate(oob), Transport(request=lambda *a, **k: (200, "ok"))).status == REJECTED


def test_verify_ssrf_excludes_grin_own_ip_open_redirect():
    # the only callback comes from grin's OWN ip (it followed an open-redirect) -> NOT ssrf
    oob = _FakeOOB()

    def request(method, url, json=None, headers=None):
        cb = urllib.parse.unquote(url.split("url=", 1)[1])
        oob.fire(cb.rsplit("/", 1)[-1], "10.0.0.1")       # grin's own IP
        return (302, "")
    assert verify(_ssrf_candidate(oob), Transport(request=request)).status == REJECTED


def _blind_cmdi_candidate(oob):
    return Candidate(vuln_class="blind-command-injection", location="/run (cmd)", url="http://t/run",
                     inject_field="cmd", oracle={"oob": oob, "ssrf_timeout": 2})


def test_verify_blind_cmd_injection_confirmed_on_oob_callback():
    oob = _FakeOOB()

    import re as _re

    def request(method, url, json=None, headers=None):
        # the target's shell runs the injected curl/wget -> OOB callback from the target IP
        mt = _re.search(r"/(tok\d+)", urllib.parse.unquote(url))
        if mt:
            oob.fire(mt.group(1), "172.30.0.7")
        return (200, "done")
    assert verify(_blind_cmdi_candidate(oob), Transport(request=request)).status == CONFIRMED


def test_verify_blind_cmd_injection_rejected_without_callback():
    oob = _FakeOOB()
    assert verify(_blind_cmdi_candidate(oob),
                  Transport(request=lambda *a, **k: (200, "done"))).status == REJECTED


def test_verify_open_redirect_confirmed_when_grin_follows_to_oob():
    # the redirect param reflects our URL; grin's client (its own IP) followed the redirect to the OOB
    oob = _FakeOOB()

    def request(method, url, json=None, headers=None):
        import re as _re
        mt = _re.search(r"/(tok\d+)", urllib.parse.unquote(url))
        if mt:
            oob.fire(mt.group(1), "10.0.0.1")     # grin's OWN ip (it followed the 3xx)
        return (200, "")
    c = Candidate(vuln_class="open-redirect", location="/go (next)", url="http://t/go",
                  inject_field="next", oracle={"oob": oob, "ssrf_timeout": 2})
    assert verify(c, Transport(request=request)).status == CONFIRMED


def test_verify_open_redirect_rejected_when_no_redirect():
    oob = _FakeOOB()
    c = Candidate(vuln_class="open-redirect", location="/go (next)", url="http://t/go",
                  inject_field="next", oracle={"oob": oob, "ssrf_timeout": 2})
    assert verify(c, Transport(request=lambda *a, **k: (200, ""))).status == REJECTED


def test_verify_ssrf_inconclusive_when_oob_unhealthy():
    assert verify(_ssrf_candidate(_FakeOOB(healthy=False)),
                  Transport(request=lambda *a, **k: (200, "ok"))).status == INCONCLUSIVE


# --- XXE ---------------------------------------------------------------------------------------
_PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
           "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")


def _xxe_candidate(oob=None, template=None):
    o = {"ssrf_timeout": 2}
    if oob is not None:
        o["oob"] = oob
    if template is not None:
        o["xml_template"] = template
    return Candidate(vuln_class="xxe", location="/parse", url="http://t/parse",
                     method="POST", oracle=o)


def _xxe_app(*, vulnerable=True, benign_errors=False, baseline_passwd=False,
             echo_raw=False, oob=None, ge_blocked=False, in_band=True):
    """A fake XML endpoint. A vulnerable parser EXPANDS external entities (file read / OOB fetch);
    echo_raw simulates a parser that echoes the raw body without expanding."""
    def attacker(u, method="GET", json=None, data=None, headers=None):
        xml = data or ""
        if "grin-xxe-baseline" in xml:
            if benign_errors:
                return (500, "")
            return (200, f"<r>{_PASSWD}</r>") if baseline_passwd else (200, "<r>grin-xxe-baseline</r>")
        if "file:///etc/passwd" in xml:
            if echo_raw:
                return (200, f"<r>{xml}</r>")              # parser did not expand; raw echo
            return (200, f"<r>{_PASSWD}</r>") if (vulnerable and in_band) else (200, "<r></r>")
        if oob is not None and ("SYSTEM" in xml or "% grin" in xml):
            import re as _re
            is_pe = "% grin" in xml
            if (is_pe or not ge_blocked) and vulnerable:
                m = _re.search(r'https?://[^"\s]+', xml)
                if m:
                    tok = m.group(0).rsplit("/", 1)[-1].replace(".dtd", "")
                    oob.fire(tok, "172.20.0.9")            # the TARGET fetched it
            return (200, "<r></r>")
        return (200, "<r></r>")
    return Transport(request=lambda *a, **k: (200, ""), by_role={"attacker": attacker})


def test_xxe_in_band_file_read_confirmed():
    assert verify(_xxe_candidate(), _xxe_app(vulnerable=True)).status == CONFIRMED


def test_xxe_raw_echo_not_confirmed():
    # parser echoes my payload (which references file:///etc/passwd) but never expands it -> REJECTED
    assert verify(_xxe_candidate(), _xxe_app(echo_raw=True)).status == REJECTED


def test_xxe_benign_errors_asymmetry_not_confirmed():
    # benign baseline 500s while attack returns passwd-ish text -> diff untrustworthy -> not CONFIRMED
    assert verify(_xxe_candidate(), _xxe_app(benign_errors=True)).status == REJECTED


def test_xxe_baseline_already_passwd_not_confirmed():
    assert verify(_xxe_candidate(), _xxe_app(baseline_passwd=True)).status == REJECTED


def test_xxe_not_vulnerable_rejected():
    assert verify(_xxe_candidate(), _xxe_app(vulnerable=False)).status == REJECTED


def test_xxe_blind_general_entity_confirmed():
    oob = _FakeOOB()
    v = verify(_xxe_candidate(oob), _xxe_app(vulnerable=True, oob=oob, in_band=False))
    assert v.status == CONFIRMED and "external entity" in v.evidence


def test_xxe_blind_parameter_entity_confirmed_when_general_blocked():
    oob = _FakeOOB()
    v = verify(_xxe_candidate(oob), _xxe_app(vulnerable=True, oob=oob, ge_blocked=True, in_band=False))
    assert v.status == CONFIRMED and "external DTD" in v.evidence


def test_xxe_blind_unhealthy_oob_rejected():
    oob = _FakeOOB(healthy=False)
    assert verify(_xxe_candidate(oob), _xxe_app(vulnerable=False, oob=oob)).status == REJECTED


def test_xxe_inconclusive_when_post_raises():
    def attacker(u, method="GET", json=None, data=None, headers=None):
        raise RuntimeError("boom")
    t = Transport(request=lambda *a, **k: (200, ""), by_role={"attacker": attacker})
    assert verify(_xxe_candidate(), t).status == INCONCLUSIVE


# --- deferred OOB finalize (one run-level poll window) -----------------------------------------
def test_assess_defers_ssrf_and_blind_cmdi_external():
    import re as _re
    from grin.engine import assess
    oob = _FakeOOB()

    def request(method, url, json=None, headers=None, data=None):
        m = _re.search(r"tok\d+", url + str(json))
        if m:
            oob.fire(m.group(0), "172.20.0.9")          # the TARGET fetched it (external)
        return (200, "ok")
    cands = [
        Candidate("ssrf", "/a (url)", "http://t/a", inject_field="url",
                  oracle={"oob": oob, "ssrf_timeout": 2}),
        Candidate("blind-command-injection", "/b (cmd)", "http://t/b", inject_field="cmd",
                  oracle={"oob": oob, "ssrf_timeout": 2}),
    ]
    classes = {f.vuln_class for f in assess(cands, Transport(request=request))}
    assert "ssrf" in classes and "command-injection" in classes


def test_assess_defers_open_redirect_grin_own_predicate():
    import re as _re
    from grin.engine import assess
    oob = _FakeOOB()

    def request(method, url, json=None, headers=None, data=None):
        m = _re.search(r"tok\d+", url)
        if m:
            oob.fire(m.group(0), "10.0.0.1")            # grin's OWN ip (followed the redirect)
        return (302, "")
    c = Candidate("open-redirect", "/r (url)", "http://t/r", inject_field="url",
                  oracle={"oob": oob, "ssrf_timeout": 2})
    assert [f.vuln_class for f in assess([c], Transport(request=request))] == ["open-redirect"]


def test_assess_oob_single_poll_window_not_per_candidate():
    import time as _t
    from grin.engine import assess
    oob = _FakeOOB()                                    # nothing ever fires
    cands = [Candidate("ssrf", f"/p{i} (url)", f"http://t/p{i}", inject_field="url",
                       oracle={"oob": oob, "ssrf_timeout": 1}) for i in range(3)]
    start = _t.monotonic()
    findings = assess(cands, Transport(request=lambda *a, **k: (200, "ok")))
    elapsed = _t.monotonic() - start
    assert findings == [] and elapsed < 2.0             # ONE ~1s window, not 3x sequential (~3s)


# --- SSRF slice 2: DNS-token arm --------------------------------------------------------------
def test_verify_ssrf_confirmed_via_dns_only_when_http_egress_filtered():
    import re as _re
    oob = _FakeOOB(dns_domain="oob.grin.test")

    def request(method, url, json=None, headers=None, data=None):
        m = _re.search(r"dtok\d+", url + str(json))
        if m:
            oob.fire_dns(m.group(0), "8.8.8.8")             # the resolver queried it; no HTTP egress
        return (200, "ok")
    v = verify(_ssrf_candidate(oob), Transport(request=request))
    assert v.status == CONFIRMED and "resolved an attacker-controlled hostname" in v.evidence


def test_verify_ssrf_http_arm_still_wins_when_dns_enabled():
    import re as _re
    oob = _FakeOOB(dns_domain="oob.grin.test")

    def request(method, url, json=None, headers=None, data=None):
        m = _re.search(r"tok\d+", url)                      # the HTTP path token (not dtok)
        if m and not m.group(0).startswith("dtok"):
            oob.fire(m.group(0), "172.20.0.9")
        return (200, "ok")
    v = verify(_ssrf_candidate(oob), Transport(request=request))
    assert v.status == CONFIRMED and "server-side request" in v.evidence


def _free_udp_port():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _dns_query(host):
    q = b"\x12\x34" + b"\x01\x00" + b"\x00\x01\x00\x00\x00\x00\x00\x00"
    for label in host.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + b"\x00\x01" + b"\x00\x01"          # QTYPE A, QCLASS IN


def test_oob_dns_capture_records_real_query():
    import socket
    import time as _t
    dport = _free_udp_port()
    oob = OOBServer(_free_port(), "http://127.0.0.1:1", bind_host="127.0.0.1",
                    dns_domain="oob.grin.test", dns_port=dport)
    oob.start()
    try:
        tok = oob.mint_dns_token()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(_dns_query(oob.dns_callback_host(tok)), ("127.0.0.1", dport))
        try:
            s.recvfrom(512)                                 # the server answers an A record
        except socket.timeout:
            pass
        deadline = _t.monotonic() + 2
        while _t.monotonic() < deadline and not oob.dns_hit_sources(tok):
            _t.sleep(0.05)
        assert oob.dns_hit_sources(tok) == {"127.0.0.1"}
    finally:
        oob.stop()
