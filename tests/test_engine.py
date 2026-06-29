from grin.engine import assess
from grin.verify import Candidate, Transport


def _ssti(path):
    return Candidate(vuln_class="ssti", location=f"{path} (param q)",
                     url=f"http://t{path}", inject_field="q")


def test_assess_emits_findings_only_for_confirmed():
    # /a is vulnerable (evaluates the payload); /b is not
    def request(method, url, json=None, headers=None):
        if "/a" in url:
            return (200, "7006652") if "1234" in url else (200, "control")
        return (200, "nothing here")
    findings = assess([_ssti("/a"), _ssti("/b")], Transport(request=request))
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_class == "ssti" and "/a" in f.location
    assert f.location and f.evidence            # carries the verdict's evidence


def test_assess_sets_severity_by_class():
    def request(method, url, json=None, headers=None):
        return (200, "7006652") if "1234" in url else (200, "control")
    findings = assess([_ssti("/a")], Transport(request=request))
    assert findings[0].severity in ("critical", "high")   # ssti is high-impact


def test_assess_empty_when_nothing_confirms():
    assert assess([_ssti("/a")], Transport(request=lambda *a, **k: (200, "no"))) == []


def test_assess_inconclusive_is_not_a_finding():
    # a verifier that can't tell (error status) must NOT produce a finding
    assert assess([_ssti("/a")], Transport(request=lambda *a, **k: (500, ""))) == []


from grin.engine import recon


def test_recon_generates_bac_sqli_ssti_candidates():
    def fetch(url):
        return (200, '<form action="/x"><input name="search"><input name="comment"></form>')
    cands = recon("http://t:3000", fetch)
    classes = {c.vuln_class for c in cands}
    assert {"broken-access-control", "sql-injection", "ssti"} <= classes
    # the discovered form param became an SSTI candidate
    assert any(c.vuln_class == "ssti" and c.inject_field == "search" for c in cands)
    # BAC candidates carry a baseline_url for the SPA-shell diff
    bac = [c for c in cands if c.vuln_class == "broken-access-control"][0]
    assert bac.oracle.get("baseline_url")
    # the SQLi candidate targets the login as a POST on the email field
    sqli = [c for c in cands if c.vuln_class == "sql-injection"][0]
    assert sqli.method == "POST" and sqli.inject_field == "email" and "login" in sqli.url


def test_recon_survives_unreachable_page():
    def fetch(url):
        raise RuntimeError("down")
    cands = recon("http://t", fetch)
    # still yields BAC + SQLi candidates from the static lists even if the page won't load
    assert {"broken-access-control", "sql-injection"} <= {c.vuln_class for c in cands}


from grin.engine import run_general


def test_run_general_finds_bac_sqli_idor_on_a_fake_vulnerable_app():
    def request(method, url, json=None, headers=None):
        if url.endswith("/rest/user/login"):
            email = (json or {}).get("email", "")
            if "OR 1=1" in email or "'--" in email:
                return (200, '{"authentication":{"token":"BYPASS"}}')       # SQLi auth bypass
            if "aaa" in email:
                return (200, '{"authentication":{"token":"TA","bid":6}}')
            return (200, '{"authentication":{"token":"TB","bid":7}}')
        if "/ftp/legal.md" in url:
            return (200, "CONFIDENTIAL legal text")                          # BAC: unauth content
        if url.rstrip("/").endswith(":3000") or url.endswith("://t:3000/"):
            return (200, "SPA-SHELL")
        if url.endswith("/"):
            return (200, "SPA-SHELL")                                       # root baseline
        authed = "Authorization" in (headers or {})
        if "/rest/basket/7" in url:                                          # the victim's object
            return (200, '{"id":7,"data":"victim-basket"}') if authed else (401, "")
        if "/rest/basket/6" in url:                                          # the attacker's own
            return (200, '{"id":6,"data":"attacker-basket"}') if authed else (401, "")
        return (404, "")
    creds = [{"email": "aaa@x", "password": "p"}, {"email": "bbb@x", "password": "p"}]
    findings = run_general("http://t:3000", creds, request=request)
    classes = {f.vuln_class for f in findings}
    assert "broken-access-control" in classes      # /ftp/legal.md
    assert "sql-injection" in classes              # login bypass
    assert "idor" in classes                       # victim basket reachable by attacker


def test_run_general_no_creds_skips_idor_but_still_finds_unauth():
    def request(method, url, json=None, headers=None):
        if "/ftp/legal.md" in url:
            return (200, "CONFIDENTIAL")
        if url.endswith("/"):
            return (200, "SHELL")
        return (404, "")
    findings = run_general("http://t:3000", None, request=request)
    classes = {f.vuln_class for f in findings}
    assert "broken-access-control" in classes
    assert "idor" not in classes                   # no creds -> no IDOR candidate


def test_build_transport_role_supports_authenticated_writes():
    # the per-role callable must carry auth into writes (method + json), not just GET reads
    from grin.engine import build_transport
    seen = {}

    def request(method, url, json=None, headers=None):
        if url.endswith("/rest/user/login"):
            return (200, '{"authentication":{"token":"TA","bid":6}}')
        seen["method"], seen["json"], seen["auth"] = method, json, (headers or {}).get("Authorization")
        return (200, "ok")
    creds = [{"email": "a@x", "password": "p"}, {"email": "b@x", "password": "p"}]
    transport, _, _ = build_transport(request, "http://t", creds)
    transport.by_role["attacker"]("http://t/w", method="POST", json={"k": "v"})
    assert seen["method"] == "POST" and seen["json"] == {"k": "v"}
    assert seen["auth"] == "Bearer TA"


def test_run_general_discovers_and_confirms_idor_via_openapi():
    # a VAmPI-shaped app: login by username->JWT, OpenAPI describes /books/v1 + detail, books are
    # owner-attributed and any authed user can read any book (BOLA). No hardcoded template is used.
    import base64
    import json as _J

    def mkjwt(claims):
        b = lambda d: base64.urlsafe_b64encode(_J.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
        return ".".join([b({"alg": "HS256"}), b(claims), "sig"])

    books = {"vbook": {"book_title": "vbook", "secret": "VS", "user": "vic"},
             "abook": {"book_title": "abook", "secret": "AS", "user": "atk"}}
    spec = {"paths": {"/books/v1": {"get": {}}, "/books/v1/{book_title}": {"get": {}}}}

    def request(method, url, json=None, headers=None):
        authed = "Authorization" in (headers or {})
        if url.endswith("/users/v1/login") and method == "POST" and "username" in (json or {}):
            return (200, _J.dumps({"auth_token": mkjwt({"sub": json["username"]})}))
        if url.endswith("/rest/user/login"):
            return (404, "")
        if url.endswith("/openapi.json"):
            return (200, _J.dumps(spec))
        if url.endswith("/books/v1"):
            return (200, _J.dumps({"Books": [dict(b) for b in books.values()]})) if authed else (401, "")
        for title, body in books.items():
            if url.endswith("/books/v1/" + title):
                return (200, _J.dumps(body)) if authed else (401, "")
        return (404, "")
    creds = [{"username": "atk", "password": "p"}, {"username": "vic", "password": "p"}]
    findings = run_general("http://t", creds, request=request)
    idor = [f for f in findings if f.location == "/books/v1/{book_title}"]
    assert idor and idor[0].vuln_class == "idor"


def test_run_general_discovers_and_confirms_mass_assignment_via_openapi():
    # OpenAPI exposes a register + /me; the server persists a client-supplied admin flag
    import base64
    import json as _J
    spec = {"paths": {"/users/v1/register": {"post": {}}, "/users/v1/login": {"post": {}},
                      "/me": {"get": {}}}}
    store = {}

    def jwt(sub):
        b = lambda d: base64.urlsafe_b64encode(_J.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
        return ".".join([b({"alg": "HS256"}), b({"sub": sub}), "sig"])

    def sub_of(headers):
        try:
            seg = (headers or {}).get("Authorization", "").replace("Bearer ", "").split(".")[1]
            return _J.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))["sub"]
        except Exception:
            return None

    def request(method, url, json=None, headers=None):
        if url.endswith("/openapi.json"):
            return (200, _J.dumps(spec))
        if method == "POST" and url.endswith("/users/v1/register"):
            b = json or {}
            store[b.get("username")] = {"admin": b.get("admin") is True}
            return (201, "{}")
        if method == "POST" and url.endswith("/users/v1/login"):
            u = (json or {}).get("username")
            return (200, _J.dumps({"auth_token": jwt(u)})) if u in store else (401, "")
        if method == "GET" and url.endswith("/me"):
            s = sub_of(headers)
            return (200, _J.dumps({"data": {"username": s, "admin": store[s]["admin"]}})) if s in store else (401, "")
        return (404, "")
    findings = run_general("http://t", None, request=request)
    ma = [f for f in findings if f.vuln_class == "mass-assignment"]
    assert ma and store     # confirmed, and accounts were actually created


def test_run_general_discovers_and_confirms_excessive_exposure_via_openapi():
    # OpenAPI exposes a /_debug data endpoint that leaks identity+password records to anon
    import json as _J
    spec = {"paths": {"/users/v1/_debug": {"get": {}}, "/createdb": {"get": {}}}}
    reset = {"hit": False}

    def request(method, url, json=None, headers=None):
        if url.endswith("/openapi.json"):
            return (200, _J.dumps(spec))
        if url.endswith("/createdb"):
            reset["hit"] = True                 # must NEVER be probed (side-effecting GET)
            return (200, "db reset")
        if url.endswith("/users/v1/_debug"):
            return (200, '{"users":[{"username":"admin","password":"pass1"}]}')
        if url.endswith("/"):
            return (200, "SHELL")
        return (404, "")
    findings = run_general("http://t", None, request=request)
    expo = [f for f in findings if f.vuln_class == "excessive-data-exposure"]
    assert expo and expo[0].location == "/users/v1/_debug"
    assert reset["hit"] is False                # recon never triggered the destructive GET


def test_run_general_discovers_and_confirms_error_sqli_via_openapi():
    # OpenAPI exposes /users/v1/{username}; the path param is injectable (quote breaks the SQL string)
    import json as _J
    spec = {"paths": {"/users/v1": {"get": {}}, "/users/v1/{username}": {"get": {}}}}

    def request(method, url, json=None, headers=None):
        if url.endswith("/openapi.json"):
            return (200, _J.dumps(spec))
        if "/users/v1/" in url:
            import urllib.parse as up
            value = up.unquote(url.rsplit("/", 1)[-1])
            if value.count("'") % 2 == 1:
                return (500, 'sqlite3.OperationalError: near "%s": syntax error' % value)
            return (200, '{"username": "%s"}' % value)
        if url.endswith("/"):
            return (200, "SHELL")
        return (404, "")
    findings = run_general("http://t", None, request=request)
    sqli = [f for f in findings if f.location == "/users/v1/{username}"]
    assert sqli and sqli[0].vuln_class == "sql-injection"


def test_build_transport_discovers_non_juice_login_shape():
    # a VAmPI-shaped API (username field, token at auth_token) the Juice-Shop default would miss
    from grin.engine import build_transport
    import base64
    import json as _J

    def mkjwt(claims):
        b = lambda d: base64.urlsafe_b64encode(_J.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
        return ".".join([b({"alg": "HS256"}), b(claims), "sig"])

    def request(method, url, json=None, headers=None):
        if url.endswith("/users/v1/login") and method == "POST" and "username" in (json or {}):
            return (200, _J.dumps({"auth_token": mkjwt({"sub": json["username"]})}))
        if url.endswith("/rest/user/login"):     # the legacy default must NOT win here
            return (404, "")
        return (200, "not-json")                  # every other probe is inert
    creds = [{"username": "atk", "password": "p"}, {"username": "vic", "password": "p"}]
    transport, _vid, _aid = build_transport(request, "http://t", creds)
    assert "attacker" in transport.by_role and "victim" in transport.by_role


def test_run_general_detects_forged_review():
    store = []

    def request(method, url, json=None, headers=None):
        if url.endswith("/rest/user/login"):
            bid = 6 if "aaa" in (json or {}).get("email", "") else 7
            tok = "TA" if bid == 6 else "TB"
            return (200, '{"authentication":{"token":"%s","bid":%d}}' % (tok, bid))
        if "/reviews" in url and method == "PUT":
            store.append({"message": (json or {}).get("message", ""),
                          "author": (json or {}).get("author", "")})   # author taken from body = vuln
            return (200, '{"status":"success"}')
        if "/reviews" in url and method == "GET":
            import json as _j
            return (200, _j.dumps({"data": list(store)}))
        if url.endswith("/"):
            return (200, "SHELL")
        return (404, "")
    creds = [{"email": "aaa@x", "password": "p"}, {"email": "bbb@x", "password": "p"}]
    findings = run_general("http://t:3000", creds, request=request)
    forged = [f for f in findings if f.location == "/rest/products/reviews"]
    assert forged and forged[0].vuln_class == "broken-access-control"


def test_assess_dedups_bare_directory_when_file_under_it_confirms():
    from grin.verify import Candidate as C

    def anon(u):
        return (200, "secret " + u) if "/ftp" in u else (200, "SHELL")
    cands = [C("broken-access-control", "/ftp/", "http://t/ftp/", oracle={"baseline_url": "http://t/"}),
             C("broken-access-control", "/ftp/legal.md", "http://t/ftp/legal.md",
               oracle={"baseline_url": "http://t/"})]
    findings = assess(cands, Transport(request=lambda *a, **k: (200, ""), by_role={"anon": anon}))
    locs = {f.location for f in findings}
    assert "/ftp/legal.md" in locs and "/ftp/" not in locs   # bare dir subsumed by the file
