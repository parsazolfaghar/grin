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
import html as _html
import json as _json
import re
import urllib.parse
import urllib.request
from html.parser import HTMLParser

_LOGIN_MARKERS = ('type="password"', "type='password'", 'name="password"', "name='password'")
_LOGOUT_MARKERS = ("logout", "log out", "sign out", "signout", "log-out", "logoff")
_USER_NAME_RE = re.compile(r"(user|email|login|account|userid|j_username)", re.I)
_LOGIN_SUBMIT_RE = re.compile(r"(log\s*-?\s*in|sign\s*-?\s*in)", re.I)
_LOGIN_LINK_RE = re.compile(r"(login|signin|sign-in|sign_in|/auth)", re.I)
_FILLABLE_TYPES = {"text", "email", "tel", "search", "url"}


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


def _identity_proven(role_session, anon_session, protected_url, username=None):
    """Login is trustworthy only with (a) the role reaching a protected resource anon cannot, with a
    different body and no login-form markers, AND (b) a POSITIVE auth signal in the role's body — a
    logout control or the username echoed. The positive signal is essential: a failed login can
    still leave a session cookie, and a protected_url that 200s for any session would otherwise bind
    an unauthenticated role and poison every downstream verdict."""
    try:
        a_s, a_b = role_session.request("GET", protected_url)
        n_s, n_b = anon_session.request("GET", protected_url)
    except Exception:
        return False
    a_b, n_b = a_b or "", n_b or ""
    if not (a_s == 200 and n_s in (401, 403, 302) and a_b != n_b
            and not any(m in a_b for m in _LOGIN_MARKERS)):
        return False
    al = a_b.lower()
    return any(m in al for m in _LOGOUT_MARKERS) or bool(username and username.lower() in al)


# --- login-form auto-discovery (slice 2) -------------------------------------------------------
class _FormParser(HTMLParser):
    """Collect every <form> with its inputs (values HTML-unescaped) and any <base href>."""

    def __init__(self):
        super().__init__()
        self.base = None
        self.forms = []
        self._cur = None
        self._textarea = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v if v is not None else "") for k, v in attrs}
        if tag == "base" and a.get("href"):
            self.base = a["href"]
        elif tag == "form":
            self._cur = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(),
                         "fields": []}
        elif self._cur is not None and tag == "input" and a.get("name") and "disabled" not in a:
            self._cur["fields"].append({"tag": "input", "name": a["name"],
                                        "type": (a.get("type") or "text").lower(),
                                        "value": _html.unescape(a.get("value", ""))})
        elif self._cur is not None and tag == "button" and a.get("name") and "disabled" not in a:
            if (a.get("type") or "submit").lower() == "submit":
                self._cur["fields"].append({"tag": "button", "name": a["name"], "type": "submit",
                                            "value": _html.unescape(a.get("value", ""))})
        elif self._cur is not None and tag == "textarea" and a.get("name"):
            self._textarea = a["name"]
            self._cur["fields"].append({"tag": "textarea", "name": a["name"], "type": "textarea",
                                        "value": ""})

    def handle_data(self, data):
        if self._cur is not None and self._textarea:
            for f in reversed(self._cur["fields"]):
                if f["tag"] == "textarea" and f["name"] == self._textarea:
                    f["value"] += data
                    break

    def handle_endtag(self, tag):
        if tag == "textarea":
            self._textarea = None
        elif tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def parse_login_form(html_text, page_url):
    """Find the login form: exactly one password input, prefer a login-ish submit then fewest
    inputs. Returns a spec {form_url, action_url, method, inputs, username_field, password_field}
    or None. Username = a name-pattern match, else the last fillable text input before the password
    (DOM order). Cross-origin actions are rejected."""
    p = _FormParser()
    try:
        p.feed(html_text or "")
    except Exception:
        return None
    cands = [(f, pw[0]) for f in p.forms
             for pw in [[x for x in f["fields"] if x["type"] == "password"]] if len(pw) == 1]
    if not cands:
        return None

    def score(item):
        form, _pw = item
        login_submit = any(x["type"] == "submit" and _LOGIN_SUBMIT_RE.search(f"{x['name']} {x['value']}")
                           for x in form["fields"])
        return (0 if login_submit else 1, len(form["fields"]))

    form, pwf = min(cands, key=score)
    fields = form["fields"]
    pw_idx = fields.index(pwf)
    fillable = [(i, f) for i, f in enumerate(fields)
                if f["tag"] == "input" and f["type"] in _FILLABLE_TYPES and f["name"] != pwf["name"]]
    user = next((f for _i, f in fillable if _USER_NAME_RE.search(f["name"])), None)
    if user is None:
        before = [f for i, f in fillable if i < pw_idx]
        user = before[-1] if before else (fillable[0][1] if fillable else None)
    if user is None:
        return None
    action = urllib.parse.urljoin(p.base or page_url, form["action"]) if form["action"] else page_url
    if urllib.parse.urlparse(action).netloc != urllib.parse.urlparse(page_url).netloc:
        return None
    return {"form_url": page_url, "action_url": action, "method": form["method"],
            "inputs": {f["name"]: f["value"] for f in fields},
            "username_field": user["name"], "password_field": pwf["name"]}


def discover_form_login(base_url, get):
    """Locate a login form: crawl the landing page for login-ish links first, then a common-path
    fallback. get(url) -> (status, body). Returns a login spec or None."""
    base = base_url.rstrip("/")
    try:
        _s, landing = get(base + "/")
    except Exception:
        landing = ""
    links = [urllib.parse.urljoin(base + "/", h)
             for h in re.findall(r'href=["\']([^"\']+)', landing or "", re.I) if _LOGIN_LINK_RE.search(h)]
    paths = ["/login", "/login.php", "/signin", "/users/sign_in", "/account/login", "/auth/login"]
    for url in dict.fromkeys(links + [base + p for p in paths]):
        try:
            _s, body = get(url)
        except Exception:
            continue
        spec = parse_login_form(body, url) if body else None
        if spec:
            return spec
    return None


def form_login_auto(session, username, password, spec):
    """Log in by re-fetching the form (fresh CSRF/hidden values), overwriting only the username and
    password inputs, and submitting every harvested field."""
    _s, body = session.request("GET", spec["form_url"])
    fresh = parse_login_form(body, spec["form_url"]) or spec
    inputs = dict(fresh.get("inputs", {}))
    inputs[fresh["username_field"]] = username
    inputs[fresh["password_field"]] = password
    if (fresh.get("method") or "post").lower() == "post":
        session.request("POST", fresh["action_url"], data=urllib.parse.urlencode(inputs))
    else:
        sep = "&" if "?" in fresh["action_url"] else "?"
        session.request("GET", fresh["action_url"] + sep + urllib.parse.urlencode(inputs))
    return True


def build_cookie_transport_auto(base_url, credentials, protected_url, *, extra_cookies=None,
                                request_full=None):
    """Auto-discover the login form, then build a cookie Transport. Roles bind only on proven login
    (fail closed). Returns (transport, n_bound, spec_or_None)."""
    from grin.verify import Transport
    rf = request_full or _make_request_full()
    seed = dict(extra_cookies or {})
    anon = CookieSession(rf, seed=seed)
    spec = discover_form_login(base_url, lambda u: anon.request("GET", u))
    by_role = {"anon": lambda u, method="GET", json=None: anon.request(method, u, json=json)}
    if spec is None:
        return Transport(request=anon.request, by_role=by_role), 0, None
    bound = 0
    for role, cred in zip(("attacker", "victim"), list(credentials or [])):
        sess = CookieSession(rf, seed=seed)
        uname = cred.get("username") or cred.get("login") or cred.get("email")
        form_login_auto(sess, uname, cred.get("password"), spec)
        if _identity_proven(sess, anon, protected_url, uname):
            by_role[role] = (lambda s: lambda u, method="GET", json=None: s.request(method, u, json=json))(sess)
            bound += 1
    return Transport(request=anon.request, by_role=by_role), bound, spec


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
        uname = cred.get("username") or cred.get("login") or cred.get("email")
        return sess if _identity_proven(sess, anon, protected_url, uname) else None

    bound = 0
    creds = list(credentials or [])
    for role, cred in zip(("attacker", "victim"), creds):
        sess = login_role(cred)
        if sess is not None:
            by_role[role] = (lambda s: lambda u, method="GET", json=None: s.request(method, u, json=json))(sess)
            bound += 1
    return Transport(request=anon.request, by_role=by_role), bound
