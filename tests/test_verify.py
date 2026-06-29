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


# --- verify_idor (reuses the two-session seam) ---

def test_verify_idor_confirmed_when_attacker_sees_victim_resource():
    body = '{"id":7,"UserId":23}'
    t = Transport(request=lambda *a, **k: (200, ""),
                  by_role={"attacker": lambda u: (200, body), "victim": lambda u: (200, body)})
    c = Candidate(vuln_class="idor", location="/rest/basket/7", url="http://t/rest/basket/7")
    assert verify(c, t).status == CONFIRMED


def test_verify_idor_rejected_when_attacker_denied():
    t = Transport(request=lambda *a, **k: (200, ""),
                  by_role={"attacker": lambda u: (401, ""), "victim": lambda u: (200, '{"id":7}')})
    c = Candidate(vuln_class="idor", location="x", url="http://t/x")
    assert verify(c, t).status == REJECTED


def test_verify_idor_inconclusive_without_sessions():
    c = Candidate(vuln_class="idor", location="x", url="http://t/x")
    assert verify(c, Transport(request=lambda *a, **k: (200, ""))).status == INCONCLUSIVE


# --- verify_sqli (POST login auth bypass) ---

def _login_request(vulnerable):
    def request(method, url, json=None, headers=None):
        email = (json or {}).get("email", "")
        if vulnerable and ("OR 1=1" in email or "'--" in email):
            return (200, '{"authentication":{"token":"T"}}')
        return (401, "Invalid email or password.")
    return request


def _sqli_candidate():
    return Candidate(vuln_class="sql-injection", location="/rest/user/login",
                     url="http://t/rest/user/login", method="POST", inject_field="email")


def test_verify_sqli_confirmed_on_auth_bypass():
    assert verify(_sqli_candidate(), Transport(request=_login_request(True))).status == CONFIRMED


def test_verify_sqli_rejected_when_login_rejects():
    assert verify(_sqli_candidate(), Transport(request=_login_request(False))).status == REJECTED


def test_verify_sqli_inconclusive_when_unreachable():
    assert verify(_sqli_candidate(),
                  Transport(request=lambda *a, **k: (0, ""))).status == INCONCLUSIVE


# --- verify_bac (unauth sensitive access, baseline-diff) ---

def _bac_candidate(path):
    return Candidate(vuln_class="broken-access-control", location=path,
                     url="http://t" + path, oracle={"baseline_url": "http://t/"})


def test_verify_bac_confirmed_sensitive_unauth():
    def anon(u):
        return (200, "CONFIDENTIAL legal text") if "ftp" in u else (200, "SPA-SHELL")
    t = Transport(request=lambda *a, **k: (200, ""), by_role={"anon": anon})
    assert verify(_bac_candidate("/ftp/legal.md"), t).status == CONFIRMED


def test_verify_bac_rejected_when_protected():
    def anon(u):
        return (401, "") if "admin" in u else (200, "SPA-SHELL")
    t = Transport(request=lambda *a, **k: (200, ""), by_role={"anon": anon})
    assert verify(_bac_candidate("/admin"), t).status == REJECTED


def test_verify_bac_rejected_when_spa_shell():
    def anon(u):
        return (200, "SPA-SHELL")     # identical to baseline -> the catch-all shell, not real content
    t = Transport(request=lambda *a, **k: (200, ""), by_role={"anon": anon})
    assert verify(_bac_candidate("/admin"), t).status == REJECTED


# --- regression locks for the Grok oracle review ---

def test_verify_sqli_rejected_on_token_shaped_value_in_401():
    # a 401 whose body happens to contain authentication.token must NOT confirm (status gate)
    def request(method, url, json=None, headers=None):
        return (401, '{"authentication":{"token":"err-token"}}')
    assert verify(_sqli_candidate(), Transport(request=request)).status == REJECTED


def test_verify_sqli_inconclusive_on_all_5xx():
    assert verify(_sqli_candidate(),
                  Transport(request=lambda *a, **k: (500, "err"))).status == INCONCLUSIVE


def test_verify_sqli_rejects_sentinel_token_value():
    def request(method, url, json=None, headers=None):
        return (200, '{"authentication":{"token":"false"}}')   # 200 but not a real session
    assert verify(_sqli_candidate(), Transport(request=request)).status == REJECTED


def test_verify_ssti_inconclusive_when_product_in_error_response():
    def handler(method, url, json):
        return (500, "stacktrace 7006652") if "1234" in url else (200, "control")
    assert verify_ssti(_ssti_candidate(), _transport(handler)).status == INCONCLUSIVE


def test_verify_bac_uses_url_path_not_decorated_location():
    def anon(u):
        return (200, "CONFIDENTIAL legal text") if "ftp" in u else (200, "SHELL")
    t = Transport(request=lambda *a, **k: (200, ""), by_role={"anon": anon})
    c = Candidate(vuln_class="broken-access-control", location="(anon) /ftp/legal.md",
                  url="http://t/ftp/legal.md", oracle={"baseline_url": "http://t/"})
    assert verify(c, t).status == CONFIRMED


# --- verify_write_authz (write-side BAC / identity forgery; the "forged-review" class) ---
import json as _J


def _reviews_role(*, overrides_field=False, cosmetic_owner=False, never_surfaces=False,
                  drop_field=False, block_forged_value=None):
    """A fake authenticated 'reviews' endpoint as a write-capable role callable.

    role(url, method="GET", json=None) -> (status, body). POST appends a review record built
    from the request body; GET returns the wrapped collection (Juice-Shop-shaped {data:[...]}).
      overrides_field=True  -> server forces author from the session (the SECURE app)
      cosmetic_owner=True   -> a separate true-owner field exposes the real (attacker) identity
      never_surfaces=True   -> writes 'succeed' (2xx) but the read never reflects them
    """
    store = []

    def role(url, method="GET", json=None):
        if method == "POST":
            body = json or {}
            author = body.get("author", "")
            if block_forged_value is not None and author == block_forged_value:
                return (403, '{"error":"forbidden"}')   # server blocks forging this identity
            rec = {"message": body.get("message", "")}
            if not drop_field:
                rec["author"] = author
            if overrides_field:
                rec["author"] = "attacker@x"          # session identity wins
            if cosmetic_owner:
                rec["userId"] = "attacker@x"          # real ownership preserved separately
            if not never_surfaces:
                store.append(rec)
            return (201, '{"status":"success"}')
        return (200, _J.dumps({"status": "success", "data": list(store)}))
    return role


def _write_authz_candidate():
    return Candidate(
        vuln_class="forged-review", location="/rest/products/reviews",
        url="http://t/rest/products/reviews",
        oracle={
            "write_url": "http://t/rest/products/reviews",
            "read_url": "http://t/rest/products/reviews",
            "body_template": {},
            "forged_field": "author", "marker_field": "message",
            "forged_value": "victim@x", "control_value": "attacker@x",
            "attacker_identity": ["attacker@x"],
        })


def test_verify_write_authz_confirmed_on_identity_forgery():
    t = Transport(request=lambda *a, **k: (200, ""),
                  by_role={"attacker": _reviews_role()})
    v = verify(_write_authz_candidate(), t)
    assert v.status == CONFIRMED
    assert v.vuln_class == "broken-access-control"      # reported class scores against the GT
    assert v.location == "/rest/products/reviews"


def test_verify_write_authz_rejected_when_server_overrides_field():
    t = Transport(request=lambda *a, **k: (200, ""),
                  by_role={"attacker": _reviews_role(overrides_field=True)})
    assert verify(_write_authz_candidate(), t).status == REJECTED


def test_verify_write_authz_rejected_when_record_exposes_true_owner():
    # the forged value persists in a cosmetic field, but a separate field still proves real ownership
    t = Transport(request=lambda *a, **k: (200, ""),
                  by_role={"attacker": _reviews_role(cosmetic_owner=True)})
    assert verify(_write_authz_candidate(), t).status == REJECTED


def test_verify_write_authz_inconclusive_when_control_write_not_surfaced():
    # writes return 2xx but the read never reflects them -> we never exercised the path
    t = Transport(request=lambda *a, **k: (200, ""),
                  by_role={"attacker": _reviews_role(never_surfaces=True)})
    assert verify(_write_authz_candidate(), t).status == INCONCLUSIVE


def test_verify_write_authz_inconclusive_without_attacker_session():
    assert verify(_write_authz_candidate(),
                  Transport(request=lambda *a, **k: (200, ""))).status == INCONCLUSIVE


def test_verify_write_authz_locates_record_in_wrapped_collection():
    # the marker must be matched inside the right record, not the wrapper object around the list
    t = Transport(request=lambda *a, **k: (200, ""),
                  by_role={"attacker": _reviews_role()})
    assert verify(_write_authz_candidate(), t).status == CONFIRMED


def test_verify_write_authz_inconclusive_when_field_not_client_reflected():
    # the server drops the attribution field entirely -> the control can't prove it round-trips
    t = Transport(request=lambda *a, **k: (200, ""),
                  by_role={"attacker": _reviews_role(drop_field=True)})
    assert verify(_write_authz_candidate(), t).status == INCONCLUSIVE


def test_verify_write_authz_rejected_when_forged_write_blocked():
    # control (attacker's own identity) succeeds, but forging the victim's identity is blocked (403)
    t = Transport(request=lambda *a, **k: (200, ""),
                  by_role={"attacker": _reviews_role(block_forged_value="victim@x")})
    assert verify(_write_authz_candidate(), t).status == REJECTED
