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


def test_verify_idor_rejected_when_resource_is_public():
    # attacker==victim, but anon ALSO gets the same bytes -> world-readable, not a BOLA
    body = '{"id":1,"name":"public product"}'
    t = Transport(request=lambda *a, **k: (200, ""),
                  by_role={"anon": lambda u: (200, body),
                           "attacker": lambda u: (200, body), "victim": lambda u: (200, body)})
    c = Candidate(vuln_class="idor", location="/products/1", url="http://t/products/1")
    assert verify(c, t).status == REJECTED


def test_verify_idor_rejected_when_shared_or_default_resource():
    # attacker reading the victim's url == victim, but the attacker's OWN resource is identical too
    # -> every authenticated user gets the same bytes (shared/empty template), not victim-specific
    same = '{"items":[]}'
    t = Transport(request=lambda *a, **k: (200, ""),
                  by_role={"anon": lambda u: (401, ""),
                           "attacker": lambda u: (200, same), "victim": lambda u: (200, same)})
    c = Candidate(vuln_class="idor", location="/cart", url="http://t/cart/victim",
                  oracle={"attacker_own_url": "http://t/cart/attacker"})
    assert verify(c, t).status == REJECTED


def test_verify_idor_confirmed_with_all_precision_layers():
    # real BOLA: attacker gets victim's exact resource, anon is denied, attacker's OWN differs
    vbody = '{"id":7,"owner":"victim","secret":"V"}'
    abody = '{"id":6,"owner":"attacker","secret":"A"}'

    def attacker(u):
        return (200, vbody) if u.endswith("/7") else (200, abody)
    t = Transport(request=lambda *a, **k: (200, ""),
                  by_role={"anon": lambda u: (401, ""),
                           "attacker": attacker, "victim": lambda u: (200, vbody)})
    c = Candidate(vuln_class="idor", location="/basket/7", url="http://t/basket/7",
                  oracle={"attacker_own_url": "http://t/basket/6"})
    assert verify(c, t).status == CONFIRMED


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


# --- verify_exposure (excessive data exposure: identity+credential to anon) ---

def _exposure_transport(status, body):
    return Transport(request=lambda *a, **k: (200, ""),
                     by_role={"anon": lambda u: (status, body)})


def _expo_cand():
    return Candidate(vuln_class="excessive-data-exposure", location="/users/v1/_debug",
                     url="http://t/users/v1/_debug")


def test_verify_exposure_confirmed_on_identity_plus_password_records():
    body = '{"users":[{"username":"admin","password":"pass1"},{"username":"bob","password":"pass2"}]}'
    assert verify(_expo_cand(), _exposure_transport(200, body)).status == CONFIRMED


def test_verify_exposure_rejected_on_public_secret_without_identity():
    # a public share-secret object (no identity + password co-location) must NOT confirm
    body = '{"room":"lobby","secret":"join-xkcd-42"}'
    assert verify(_expo_cand(), _exposure_transport(200, body)).status == REJECTED


def test_verify_exposure_rejected_on_identity_only_listing():
    body = '{"users":["admin","bob","carol"]}'      # usernames only, no credentials
    assert verify(_expo_cand(), _exposure_transport(200, body)).status == REJECTED


def test_verify_exposure_rejected_in_openapi_schema_subtree():
    # {password: "string"} under a schema is a TYPE, not a leak
    body = '{"components":{"schemas":{"User":{"properties":{"username":{"type":"string"},"password":{"type":"string"}}}}}}'
    assert verify(_expo_cand(), _exposure_transport(200, body)).status == REJECTED


def test_verify_exposure_rejected_on_masked_value():
    body = '{"users":[{"username":"admin","password":"****"}]}'
    assert verify(_expo_cand(), _exposure_transport(200, body)).status == REJECTED


def test_verify_exposure_rejected_when_restricted():
    assert verify(_expo_cand(), _exposure_transport(401, "")).status == REJECTED


def test_verify_exposure_inconclusive_on_server_error():
    assert verify(_expo_cand(), _exposure_transport(500, "")).status == INCONCLUSIVE


def test_verify_exposure_rejected_on_non_json():
    assert verify(_expo_cand(), _exposure_transport(200, "<html>hello</html>")).status == REJECTED


# --- verify_error_sqli (error-based, data-extraction SQLi) ---

def _esqli_candidate():
    return Candidate(vuln_class="sqli-error", location="/users/v1/{username}",
                     url="http://t/users/v1/{username}",
                     oracle={"inject": "path", "url_template": "http://t/users/v1/{inject}"})


def _esqli_transport(handler):
    # handler(value_from_url) -> (status, body); we recover the injected value from the path
    def request(method, url, json=None, headers=None):
        import urllib.parse as up
        value = up.unquote(url.rsplit("/", 1)[-1])
        return handler(value)
    return Transport(request=request)


def test_verify_error_sqli_confirmed_on_quote_break_with_echo():
    # a single quote (odd) breaks; the doubled quote (even) is fine; the DB error echoes our marker
    def handler(value):
        if value.count("'") % 2 == 1:
            return (500, f'sqlite3.OperationalError: near "{value}": syntax error')
        return (200, '{"username": "%s"}' % value)
    assert verify(_esqli_candidate(), _esqli_transport(handler)).status == CONFIRMED


def test_verify_error_sqli_rejected_on_generic_500_without_db_signature():
    # any malformed input 500s, but with a NullPointer-style error, no DB signature
    def handler(value):
        if "'" in value:
            return (500, "java.lang.NullPointerException at Handler.process")
        return (200, "ok")
    assert verify(_esqli_candidate(), _esqli_transport(handler)).status == REJECTED


def test_verify_error_sqli_rejected_when_signature_always_present():
    # the page always shows a SQL banner (ORM debug) -> in baseline too -> not a differential
    def handler(value):
        return (200, "powered by sqlalchemy; result ok")
    assert verify(_esqli_candidate(), _esqli_transport(handler)).status == REJECTED


def test_verify_error_sqli_rejected_without_payload_echo():
    # DB error appears on the quote but does NOT echo our marker (generic SQL 500, not our input)
    def handler(value):
        if value.count("'") % 2 == 1:
            return (500, "sqlite3.OperationalError: database is locked")
        return (200, "ok")
    assert verify(_esqli_candidate(), _esqli_transport(handler)).status == REJECTED


def test_verify_error_sqli_inconclusive_on_unstable_baseline():
    state = {"n": 0}

    def handler(value):
        state["n"] += 1
        return (200, f"nonce-{state['n']}")     # baseline differs between identical requests
    assert verify(_esqli_candidate(), _esqli_transport(handler)).status == INCONCLUSIVE


def test_verify_error_sqli_inconclusive_on_waf_block():
    def handler(value):
        return (403, "blocked") if "'" in value else (200, "ok")
    assert verify(_esqli_candidate(), _esqli_transport(handler)).status == INCONCLUSIVE


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
