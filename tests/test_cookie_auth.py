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
                return (200, "SECRET DASHBOARD <a href='/logout'>Logout</a>", [])
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


from grin.cookie_auth import parse_login_form, discover_form_login, build_cookie_transport_auto


_DVWA_LOGIN = '''<html><body>
  <form action="login.php" method="post">
    <input type="text" name="username">
    <input type="password" name="password">
    <input type="hidden" name="user_token" value="ab12&amp;cd34">
    <input type="submit" name="Login" value="Login">
  </form></body></html>'''


def test_parse_login_form_extracts_fields_and_unescapes_csrf():
    spec = parse_login_form(_DVWA_LOGIN, "http://t/login.php")
    assert spec["username_field"] == "username" and spec["password_field"] == "password"
    assert spec["action_url"] == "http://t/login.php" and spec["method"] == "post"
    assert spec["inputs"]["user_token"] == "ab12&cd34"        # HTML-unescaped
    assert spec["inputs"]["Login"] == "Login"                 # submit harvested


def test_parse_login_form_picks_login_not_search_or_register():
    html = '''<form action="/search"><input type="text" name="q"></form>
      <form action="/login" method="post"><input name="user"><input type="password" name="pass">
      <input type="submit" name="signin" value="Sign in"></form>
      <form action="/register" method="post"><input name="email"><input type="password" name="p1">
      <input type="password" name="p2"></form>'''
    spec = parse_login_form(html, "http://t/")
    # the register form has TWO passwords (rejected); the search form has none; login wins
    assert spec["action_url"] == "http://t/login" and spec["password_field"] == "pass"


def test_parse_login_form_username_is_last_text_before_password():
    html = '''<form method="post"><input type="text" name="company"><input type="text" name="acct">
      <input type="password" name="pw"><input type="submit" name="go" value="Log in"></form>'''
    spec = parse_login_form(html, "http://t/login")
    assert spec["username_field"] == "acct"     # last fillable before the password (no name match)


def test_parse_login_form_rejects_cross_origin_action():
    html = '<form action="https://evil.test/login" method="post"><input name="u"><input type="password" name="p"></form>'
    assert parse_login_form(html, "http://t/login") is None


def test_discover_form_login_follows_landing_link():
    def get(url):
        if url.rstrip("/") == "http://t":
            return (200, '<a href="/login.php">Sign in</a>')
        if url.endswith("/login.php"):
            return (200, _DVWA_LOGIN)
        return (404, "")
    spec = discover_form_login("http://t", get)
    assert spec and spec["action_url"] == "http://t/login.php"


def test_build_cookie_transport_auto_discovers_and_binds():
    t, n, spec = build_cookie_transport_auto(
        "http://t", [{"username": "admin", "password": "pw"}], "http://t/protected",
        request_full=_auto_cookie_server())
    assert n == 1 and "attacker" in t.by_role and spec["password_field"] == "password"


def _auto_cookie_server():
    # like _cookie_server but the login page is auto-discovered from "/" and uses a real <form>
    sessions, counter = {}, {"n": 0}

    def request_full(method, url, json=None, data=None, headers=None):
        jar = {}
        for part in (headers or {}).get("Cookie", "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                jar[k] = v
        if url.rstrip("/") == "http://t" and method == "GET":
            return (200, '<a href="/login">Login</a>', [])
        if url.endswith("/login") and method == "GET":
            counter["n"] += 1
            sid = f"sid{counter['n']}"
            sessions[sid] = False
            form = ('<form action="/login" method="post"><input name="username">'
                    '<input type="password" name="password">'
                    '<input type="hidden" name="user_token" value="TOK"><input type="submit" name="Login" value="Login"></form>')
            return (200, form, [("Set-Cookie", f"SESSID={sid}; Path=/")])
        if url.endswith("/login") and method == "POST":
            form = dict(urllib.parse.parse_qsl(data or ""))
            sid = jar.get("SESSID")
            if form.get("username") == "admin" and form.get("password") == "pw" and form.get("user_token") == "TOK" and sid in sessions:
                sessions[sid] = True
                return (302, "", [("Location", "/")])
            return (200, '<input type="password" name="password">', [])
        if url.endswith("/protected"):
            sid = jar.get("SESSID")
            if sid and sessions.get(sid):
                return (200, "DASH <a href='/logout'>Logout</a>", [])
            return (302, "", [("Location", "/login")])
        return (404, "", [])
    return request_full


def test_error_sqli_probes_through_the_attacker_session():
    seen = {"used_attacker": False}

    def attacker(u, method="GET", json=None):
        seen["used_attacker"] = True
        v = urllib.parse.unquote(u.rsplit("=", 1)[-1])
        return (200, f'you have an error in your sql syntax near "{v}"') if v.count("'") % 2 else (200, "ok")
    t = Transport(request=lambda *a, **k: (404, ""), by_role={"attacker": attacker})
    c = Candidate(vuln_class="sqli-error", location="/x", url="http://t/x", inject_field="id")
    assert verify(c, t).status == CONFIRMED and seen["used_attacker"]
