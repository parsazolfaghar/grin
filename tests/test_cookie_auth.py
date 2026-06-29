import urllib.parse

from grin.cookie_auth import (
    build_cookie_transport, form_login, CookieSession, _parse_set_cookies, _extract_csrf,
)
from grin.verify import verify, Candidate, Transport, CONFIRMED


def _cookie_server():
    """A faithful-enough cookie app: GET /login sets a session cookie + serves a CSRF token; POST
    /login authenticates the session (302 + Set-Cookie) iff creds + token are right; /protected is
    200 only for an authenticated session, else 302 to /login."""
    sessions = {}
    counter = {"n": 0}

    def request_full(method, url, json=None, data=None, headers=None):
        jar = {}
        for part in (headers or {}).get("Cookie", "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                jar[k] = v
        if url.endswith("/login") and method == "GET":
            counter["n"] += 1
            sid = f"sid{counter['n']}"
            sessions[sid] = False
            return (200, '<input name="user_token" value="TOK123">', [("Set-Cookie", f"SESSID={sid}; Path=/; HttpOnly")])
        if url.endswith("/login") and method == "POST":
            form = dict(urllib.parse.parse_qsl(data or ""))
            sid = jar.get("SESSID")
            if (form.get("username") == "admin" and form.get("password") == "pw"
                    and form.get("user_token") == "TOK123" and sid in sessions):
                sessions[sid] = True
                return (302, "", [("Location", "/index"), ("Set-Cookie", f"SESSID={sid}; Path=/")])
            return (200, '<input name="password" type="password"> bad login', [])
        if url.endswith("/protected"):
            sid = jar.get("SESSID")
            if sid and sessions.get(sid):
                return (200, "SECRET DASHBOARD value=42", [])
            return (302, "", [("Location", "/login")])
        return (404, "", [])
    return request_full


def test_parse_set_cookies_keeps_value_drops_attributes_and_evicts():
    hdrs = [("Set-Cookie", "PHPSESSID=abc123; Path=/; HttpOnly"),
            ("Set-Cookie", "old=; Max-Age=0"), ("Content-Type", "text/html")]
    out = list(_parse_set_cookies(hdrs))
    assert ("PHPSESSID", "abc123", False) in out
    assert ("old", "", True) in out


def test_extract_csrf_handles_both_orderings():
    assert _extract_csrf('<input name="user_token" value="AAA">', "user_token") == "AAA"
    assert _extract_csrf("<input value='BBB' name='user_token'>", "user_token") == "BBB"
    assert _extract_csrf("<p>no token here</p>", "user_token") is None


def test_cookie_session_carries_and_absorbs_cookies():
    log = []

    def rf(method, url, json=None, data=None, headers=None):
        log.append((headers or {}).get("Cookie"))
        return (200, "ok", [("Set-Cookie", "A=1; Path=/")])
    s = CookieSession(rf, seed={"security": "low"})
    s.request("GET", "http://t/")           # sends seed, absorbs A=1
    s.request("GET", "http://t/")           # now sends both
    assert "security=low" in log[1] and "A=1" in log[1]


def test_build_cookie_transport_binds_authenticated_role():
    t, n = build_cookie_transport(
        "http://t", "http://t/login", [{"username": "admin", "password": "pw"}],
        "http://t/protected", csrf_field="user_token", request_full=_cookie_server())
    assert n == 1 and "attacker" in t.by_role
    status, body = t.by_role["attacker"]("http://t/protected")
    assert status == 200 and "SECRET" in body


def test_build_cookie_transport_fails_closed_on_bad_login():
    # wrong password -> login not proven -> role NOT bound (fail closed)
    t, n = build_cookie_transport(
        "http://t", "http://t/login", [{"username": "admin", "password": "WRONG"}],
        "http://t/protected", csrf_field="user_token", request_full=_cookie_server())
    assert n == 0 and "attacker" not in t.by_role


def test_form_login_fails_closed_when_csrf_field_absent():
    def rf(method, url, json=None, data=None, headers=None):
        return (200, "<form>no token</form>", [])
    assert form_login(CookieSession(rf), "http://t/login",
                      {"username": "a", "password": "b"}, csrf_field="user_token") is False


def test_error_sqli_probes_through_the_attacker_session():
    seen = {"used_attacker": False}

    def attacker(u, method="GET", json=None):
        seen["used_attacker"] = True
        v = urllib.parse.unquote(u.rsplit("=", 1)[-1])
        return (200, f'you have an error in your sql syntax near "{v}"') if v.count("'") % 2 else (200, "ok")
    t = Transport(request=lambda *a, **k: (404, ""), by_role={"attacker": attacker})
    c = Candidate(vuln_class="sqli-error", location="/x", url="http://t/x", inject_field="id")
    assert verify(c, t).status == CONFIRMED and seen["used_attacker"]
