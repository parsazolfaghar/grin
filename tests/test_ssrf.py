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
    def __init__(self, healthy=True):
        self._healthy = healthy
        self._hits = {}
        self._n = 0

    def healthy(self):
        return self._healthy

    def mint_token(self):
        self._n += 1
        return f"tok{self._n}"

    def callback_url(self, token):
        return f"http://oob.test/{token}"

    def grin_ips(self):
        return {"10.0.0.1"}

    def hit_sources(self, token):
        return self._hits.get(token, set())

    def fire(self, token, ip):
        self._hits.setdefault(token, set()).add(ip)


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


def test_verify_ssrf_inconclusive_when_oob_unhealthy():
    assert verify(_ssrf_candidate(_FakeOOB(healthy=False)),
                  Transport(request=lambda *a, **k: (200, "ok"))).status == INCONCLUSIVE
