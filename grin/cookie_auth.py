"""Cookie/session authentication support — lets the verifiers work on apps that authenticate with
a Set-Cookie session (e.g. DVWA: form login + CSRF token + PHPSESSID) instead of a JWT bearer.

Design (adversarial-reviewed). The cookie state lives entirely inside per-role closures; verifiers
keep the unchanged (status, body) contract. Each role gets its OWN isolated cookie jar, so an
attacker's session can never leak into anon. The critical correctness points:
  - redirects are NOT followed (urllib would swallow the Set-Cookie on a login 302) — we read each
    hop's headers directly;
  - a role is only bound once login is PROVEN (status asymmetry vs anon + body diff + no login-form
    markers), failing closed otherwise;
  - extra cookies (e.g. DVWA's security=low) are seeded into every jar, including anon.

Scope (slice 1): the login URL, credential field names, and CSRF field are CONFIGURED (the harness
is pointed at them). Auto-discovering cookie/form/CSRF logins is a deferred follow-up."""
from __future__ import annotations
import json as _json
import re
import urllib.parse
import urllib.request

_LOGIN_MARKERS = ('type="password"', "type='password'", 'name="password"', "name='password'")


def _make_request_full():
    """Low-level request that returns (status, body, headers) and does NOT follow redirects."""
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(_NoRedirect)

    def request_full(method, url, json=None, data=None, headers=None):
        import urllib.error
        h = dict(headers or {})
        body = None
        if json is not None:
            body = _json.dumps(json).encode()
            h.setdefault("Content-Type", "application/json")
        elif data is not None:
            body = data.encode() if isinstance(data, str) else data
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        req = urllib.request.Request(url, data=body, method=method, headers=h)
        try:
            r = opener.open(req, timeout=10)
            return r.status, r.read(262144).decode("utf-8", "replace"), list(r.getheaders())
        except urllib.error.HTTPError as e:
            return e.code, e.read(8192).decode("utf-8", "replace"), list(e.headers.items())
        except Exception:
            return 0, "", []
    return request_full


def _parse_set_cookies(headers):
    """Yield (name, value, evict) from Set-Cookie response headers. evict=True for deletions
    (Max-Age=0 / empty value). Only the name=value pair is kept; attributes are dropped."""
    for name, raw in headers:
        if name.lower() != "set-cookie":
            continue
        first, _, attrs = raw.partition(";")
        if "=" not in first:
            continue
        ck, _, cv = first.strip().partition("=")
        ck = ck.strip()
        evict = (cv.strip() == "") or re.search(r"max-age=0(\b|;|$)", attrs, re.I) is not None
        yield ck, cv.strip(), evict


class CookieSession:
    """A request surface backed by one isolated cookie jar. request(...) attaches the jar's cookies
    and absorbs Set-Cookie from each response."""

    def __init__(self, request_full, seed=None):
        self.jar = dict(seed or {})
        self._rf = request_full

    def request(self, method, url, json=None, data=None, headers=None):
        h = dict(headers or {})
        if self.jar:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.jar.items())
        status, body, rheaders = self._rf(method, url, json=json, data=data, headers=h)
        for name, value, evict in _parse_set_cookies(rheaders):
            if evict:
                self.jar.pop(name, None)
            else:
                self.jar[name] = value
        return status, body


def _extract_csrf(body, field):
    """Find a CSRF token value for a named hidden input (handles attribute ordering + quote style)."""
    for pat in (rf'name=["\']{re.escape(field)}["\'][^>]*?value=["\']([^"\']+)',
                rf'value=["\']([^"\']+)["\'][^>]*?name=["\']{re.escape(field)}["\']'):
        m = re.search(pat, body or "", re.I)
        if m:
            return m.group(1)
    return None


def form_login(session, login_url, fields, csrf_field=None):
    """Drive a form login on `session` (its jar ends up authenticated). Returns True if the login
    was attempted; a configured-but-missing CSRF field fails closed (False)."""
    _s, body = session.request("GET", login_url)     # capture the pre-session cookie + CSRF token
    payload = dict(fields)
    if csrf_field:
        token = _extract_csrf(body, csrf_field)
        if token is None:
            return False
        payload[csrf_field] = token
    session.request("POST", login_url, data=urllib.parse.urlencode(payload))
    return True


def _identity_proven(role_session, anon_session, protected_url):
    """Login is trustworthy only if the role reaches a protected resource the anon session cannot,
    with a different body and no login-form markers — not a bare 200 (which a public page or a
    failed-login error page would also give)."""
    try:
        a_s, a_b = role_session.request("GET", protected_url)
        n_s, n_b = anon_session.request("GET", protected_url)
    except Exception:
        return False
    return (a_s == 200 and n_s in (401, 403, 302) and (a_b or "") != (n_b or "")
            and not any(m in (a_b or "") for m in _LOGIN_MARKERS))


def build_cookie_transport(base_url, login_url, credentials, protected_url, *,
                           username_field="username", password_field="password",
                           extra_login_fields=None, csrf_field=None, extra_cookies=None,
                           request_full=None):
    """Build a Transport whose roles authenticate via cookie sessions. Roles are bound only when
    their login is proven (fail closed). Returns (transport, n_roles_bound)."""
    from grin.verify import Transport
    rf = request_full or _make_request_full()
    seed = dict(extra_cookies or {})
    anon = CookieSession(rf, seed=seed)
    by_role = {"anon": lambda u, method="GET", json=None: anon.request(method, u, json=json)}

    def login_role(cred):
        sess = CookieSession(rf, seed=seed)
        fields = {username_field: cred.get("username") or cred.get("login") or cred.get("email"),
                  password_field: cred.get("password")}
        fields.update(extra_login_fields or {})
        if not form_login(sess, login_url, fields, csrf_field):
            return None
        return sess if _identity_proven(sess, anon, protected_url) else None

    bound = 0
    creds = list(credentials or [])
    for role, cred in zip(("attacker", "victim"), creds):
        sess = login_role(cred)
        if sess is not None:
            by_role[role] = (lambda s: lambda u, method="GET", json=None: s.request(method, u, json=json))(sess)
            bound += 1
    return Transport(request=anon.request, by_role=by_role), bound
