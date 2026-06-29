"""Authenticated crawler — the last piece for cookie-app autonomy: walk the logged-in session and
emit injection points (GET params) for the verifiers, on apps with no OpenAPI to read.

SAFETY IS THE SPINE (adversarial-reviewed). An authenticated crawl that follows the wrong link can
log itself out or mutate state, and the verifier is NOT a safety net for a bad visit. So:
  - classify every URL READ-ONLY before visiting: same-origin, GET, no action path segment, no
    action-ish query key/value (do=/action=/cmd= or a logout/delete/reset value);
  - a deauth HALT: if a fetched page shows login markers (or the logout marker vanished), stop the
    whole crawl and emit ZERO candidates — never crawl/inject a deauthenticated session;
  - never emit injection points from a form containing a password input (login/auth forms);
  - GET by default; POST forms are probed ONLY behind an explicit opt-in (allow_post for
    compute/lookup archetypes, allow_destructive for content sinks) since submitting them mutates;
  - hard caps: unique paths, candidates, per-path-prefix, depth.

Junk params (csrf/session/submit/pagination/tracking/password) are dropped at emission. The
verifier is the precision gate for WHAT confirms; this module guarantees SAFE visiting."""
from __future__ import annotations
import re
import urllib.parse

from grin.cookie_auth import _FormParser, _LOGIN_MARKERS, _LOGOUT_MARKERS, _FILLABLE_TYPES
from grin.resource_discovery import _ACTION_SEGMENTS

_DENY_SEGMENTS = _ACTION_SEGMENTS | {"logout", "signout", "signoff", "logoff", "exit", "setup",
                                     "install", "uninstall", "update", "edit", "settings", "config"}
_QUERY_ACTION_KEYS = {"do", "action", "op", "cmd", "task", "func", "mode"}
_ACTION_VALUE_RE = re.compile(
    r"\b(logout|signout|log-?off|delete|remove|destroy|drop|reset|disable|deactivate|setup|install)\b", re.I)
_SKIP_PARAM_RE = re.compile(
    r"^(csrf.*|.*_token|token|nonce|authenticity_token|session.*|.*sessid|api_?key|key|submit|"
    r"page|offset|limit|start|sort|order|dir|utm_.*|ref|source|password|passwd|pwd|user_token)$", re.I)
_HREF_RE = re.compile(r'href=["\']([^"\']+)', re.I)
_RESOURCE_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff",
                 ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz", ".map", ".mp4", ".webp", ".xml")


def _classify_readonly(url, start):
    """True only if `url` is safe to GET under the session: same-origin, no action path segment, no
    action-ish query key/value. Imperfect without app knowledge, but the best static guard."""
    pu, su = urllib.parse.urlparse(url), urllib.parse.urlparse(start)
    if pu.scheme not in ("http", "https"):
        return False
    if (pu.scheme, pu.hostname, pu.port) != (su.scheme, su.hostname, su.port):
        return False
    if pu.path.lower().endswith(_RESOURCE_EXT):      # stylesheets/scripts/images are not pages
        return False
    for seg in (s for s in pu.path.split("/") if s):
        sl = seg.lower()
        base = sl.split(".")[0]      # strip extension so logout.php / setup.php still match
        if (sl in _DENY_SEGMENTS or base in _DENY_SEGMENTS or base.endswith("db")
                or base.startswith(("create", "delete", "reset", "drop"))):
            return False
    for k, v in urllib.parse.parse_qsl(pu.query):
        if k.lower() in _QUERY_ACTION_KEYS or _ACTION_VALUE_RE.search(v):
            return False
    return True


# POST-form ALLOWLIST (positive match — Grok: a denylist can't infer server-side intent). Only
# compute/lookup-style forms are probed, each mapped to the classes whose probe is safe there.
# NEVER reflected-xss on POST (stored-XSS damage). NEVER mutating archetypes (no positive match).
_EXEC_RE = re.compile(r"(exec|command|cmd|run|ping|host|^ip$|system|shell|nslookup|traceroute|dns|whois)", re.I)
_FILE_RE = re.compile(r"(file|path|page|include|read|load|template|^doc$|filename|download)", re.I)
_QUERY_RE = re.compile(r"(search|query|filter|lookup|find|keyword|term|^q$)", re.I)


def _post_archetype_classes(action, field):
    """Positive allowlist: only compute/lookup POST forms get probed, mapped to safe classes.
    Returns [] (skip) for anything that isn't clearly a non-persistent compute/lookup form."""
    a, f = action.lower(), field.lower()
    if _EXEC_RE.search(a) or _EXEC_RE.search(f):
        return ["command-injection"]
    if _FILE_RE.search(a) or _FILE_RE.search(f):
        return ["path-traversal", "sqli-error"]
    if _QUERY_RE.search(a) or _QUERY_RE.search(f):
        return ["sqli-error"]
    return []


# CONTENT-sink forms persist attacker text that later renders (guestbook/comment/message/profile).
# These are the stored-XSS archetype the compute/lookup allowlist deliberately excludes -> they are
# gated behind allow_destructive (a WRITE), separate from the allow_post compute/lookup probes.
_CONTENT_RE = re.compile(
    r"(comment|message|guestbook|sign|^name$|txtname|fullname|^bio$|^body$|^text$|review|"
    r"feedback|^content$|description|^subject$|^post$|^note$|^msg$)", re.I)


def _post_content_classes(action, field):
    """Allowlist for persistent content sinks (stored-XSS). DESTRUCTIVE (writes content) -> the
    caller must opt in via allow_destructive. Returns ['stored-xss'] for a content field, else []."""
    a, f = action.lower(), field.lower()
    if _CONTENT_RE.search(a) or _CONTENT_RE.search(f):
        return ["stored-xss"]
    return []


def _looks_html(body):
    s = (body or "").lstrip()
    return bool(s) and s[:1] not in "{[" and "<" in s[:1024]


def _forms(body):
    p = _FormParser()
    try:
        p.feed(body or "")
    except Exception:
        return []
    return p.forms


def crawl_injection_points(start_url, fetch, *, max_pages=30, max_candidates=50, max_depth=3,
                           per_prefix=3, allow_post=False, allow_destructive=False, post_out=None):
    """BFS the authenticated session for GET injection points. fetch(url)->(status, body) must use
    the attacker session. Returns (candidates, status) where status is 'ok' or 'deauth'; candidates
    are (location, url, inject_field) for the error-SQLi verifier. Emits ZERO on deauth."""
    start = start_url

    def session_ok(body):
        # Deauth = the response IS the login page: a password input AND no logout control. A password
        # input alone is NOT deauth (brute-force / change-password pages have one); a minimal authed
        # page that simply lacks the menu (a source/help popup) is NOT deauth either.
        bl = (body or "").lower()
        looks_like_login = any(m.lower() in bl for m in _LOGIN_MARKERS)
        has_logout = any(m in bl for m in _LOGOUT_MARKERS)
        return not (looks_like_login and not has_logout)

    seen, seen_cands, prefix_count, out = set(), set(), {}, []
    queue = [(start, 0)]
    while queue and len(seen) < max_pages and len(out) < max_candidates:
        url, depth = queue.pop(0)
        url = urllib.parse.urldefrag(url)[0]
        if url in seen or not _classify_readonly(url, start):
            continue
        prefix = "/".join(urllib.parse.urlparse(url).path.split("/")[:3])
        if prefix_count.get(prefix, 0) >= per_prefix:
            continue
        seen.add(url)
        prefix_count[prefix] = prefix_count.get(prefix, 0) + 1
        try:
            st, body = fetch(url)
        except Exception:
            continue
        if st != 200 or not body:
            continue                     # a 404/redirect/empty page is not a deauth signal
        if not _looks_html(body):
            continue                     # non-HTML (CSS/JS/JSON) is not a page and not a deauth signal
        if not session_ok(body):
            if post_out is not None:     # also drop any POST candidates collected before the deauth
                post_out.clear()
            return [], "deauth"          # halt + discard everything: never inject a dead session
        pu = urllib.parse.urlparse(url)
        # injection points: query params already on this URL
        for k, _v in urllib.parse.parse_qsl(pu.query):
            if not _SKIP_PARAM_RE.match(k):
                base = url.split("?", 1)[0]
                others = [(kk, vv) for kk, vv in urllib.parse.parse_qsl(pu.query) if kk != k]
                _emit(out, seen_cands, base, others, k, pu.path)
        # injection points from forms (skip any form with a password input = login/auth form)
        for form in _forms(body):
            method = (form["method"] or "get").lower()
            if any(f["type"] == "password" for f in form["fields"]):
                continue
            action = urllib.parse.urljoin(url, form["action"]) if form["action"] else url.split("?", 1)[0]
            action = urllib.parse.urldefrag(action)[0]      # action="#" -> the page itself, no fragment
            inject = [f["name"] for f in form["fields"]
                      if f.get("name") and not _SKIP_PARAM_RE.match(f["name"])
                      and ((f["tag"] == "input" and f["type"] in _FILLABLE_TYPES) or f["tag"] == "textarea")]
            if method == "get":
                if not _classify_readonly(action, start):
                    continue
                inputs = [(f["name"], f["value"]) for f in form["fields"] if f.get("name")]
                for tf in inject:
                    fixed = [(k, v) for k, v in inputs if k != tf]
                    _emit(out, seen_cands, action, fixed, tf, urllib.parse.urlparse(action).path)
            elif method == "post" and post_out is not None and (allow_post or allow_destructive):
                # OPT-IN only. Positive archetype allowlist + per-archetype class gating; the verifier
                # re-fetches `url` for a fresh CSRF and POSTs form-encoded. allow_post -> compute/lookup
                # probes; allow_destructive -> persistent content sinks (stored-XSS, a WRITE).
                if not _classify_readonly(action, start):
                    continue
                apath = urllib.parse.urlparse(action).path
                for tf in inject:
                    classes = _post_archetype_classes(action, tf) if allow_post else []
                    if allow_destructive:
                        classes = classes + [c for c in _post_content_classes(action, tf) if c not in classes]
                    key = ("POST", action, tf)
                    if classes and key not in seen_cands:
                        seen_cands.add(key)
                        post_out.append({"location": f"{apath} ({tf}) [POST]", "action": action,
                                         "form_url": url, "field": tf, "classes": classes})
        if depth < max_depth:
            for href in _HREF_RE.findall(body):
                nxt = urllib.parse.urljoin(url, href)
                if nxt not in seen and _classify_readonly(nxt, start):
                    queue.append((nxt, depth + 1))
    return out, "ok"


def _emit(out, seen_cands, base, fixed_params, inject_field, path):
    key = (base, tuple(sorted(k for k, _v in fixed_params)), inject_field)
    if key in seen_cands:
        return
    seen_cands.add(key)
    url = base + ("?" + urllib.parse.urlencode(fixed_params) if fixed_params else "")
    out.append((f"{path} ({inject_field})", url, inject_field))
