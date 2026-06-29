from grin.verify import (
    verify, verify_ssti, Verdict, Candidate, Transport,
    CONFIRMED, REJECTED, INCONCLUSIVE,
)


def _transport(handler):
    # handler(method, url, json) -> (status, body)
    return Transport(request=lambda method, url, json=None, headers=None: handler(method, url, json))


def _ssti_candidate():
    return Candidate(vuln_class="ssti", location="/s (param q)", url="http://t/s", inject_field="q")


def test_verify_ssti_confirmed_when_payload_evaluates():
    def handler(method, url, json):
        return (200, "result 7006652") if "1234" in url else (200, "result control")
    v = verify_ssti(_ssti_candidate(), _transport(handler))
    assert isinstance(v, Verdict)
    assert v.status == CONFIRMED and v.vuln_class == "ssti" and "q" in v.location


def test_verify_ssti_rejected_when_payload_echoed_literally():
    def handler(method, url, json):
        return (200, "result {{1234*5678}}") if "1234" in url else (200, "result control")
    assert verify_ssti(_ssti_candidate(), _transport(handler)).status == REJECTED


def test_verify_ssti_no_false_positive_when_product_already_on_page():
    # the page naturally contains 7006652 (e.g. an order id) in BOTH baseline and payload responses
    def handler(method, url, json):
        return (200, "order 7006652 confirmed")
    assert verify_ssti(_ssti_candidate(), _transport(handler)).status == REJECTED


def test_verify_ssti_inconclusive_on_waf_or_error_status():
    # 403/500 is "couldn't test cleanly", NOT a clean negative
    def handler(method, url, json):
        return (403, "blocked by waf")
    assert verify_ssti(_ssti_candidate(), _transport(handler)).status == INCONCLUSIVE


def test_verify_ssti_inconclusive_on_exception():
    def handler(method, url, json):
        raise RuntimeError("connection refused")
    assert verify_ssti(_ssti_candidate(), _transport(handler)).status == INCONCLUSIVE


def test_verify_ssti_post_uses_json_body():
    seen = {}

    def handler(method, url, json):
        seen["method"] = method
        seen["json"] = json
        return (200, "7006652") if (json and "1234" in str(json)) else (200, "x")
    c = Candidate(vuln_class="ssti", location="/s", url="http://t/s", method="POST", inject_field="q")
    verify_ssti(c, _transport(handler))
    assert seen["method"] == "POST" and "1234" in str(seen["json"])


def test_verify_dispatcher_routes_by_class():
    def handler(method, url, json):
        return (200, "7006652") if "1234" in url else (200, "c")
    assert verify(_ssti_candidate(), _transport(handler)).status == CONFIRMED


def test_verify_dispatcher_unknown_class_is_inconclusive():
    c = Candidate(vuln_class="does-not-exist", location="x", url="http://t")
    v = verify(c, _transport(lambda m, u, j: (200, "")))
    assert v.status == INCONCLUSIVE
