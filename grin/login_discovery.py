"""Deterministic login-shape discovery — the first slice of generalizing recon beyond one app.

The session-coupled verifiers (IDOR, SQLi-auth-bypass, write-side BAC) are proven, but recon used
to hardcode ONE app's login (Juice Shop). This finds, per target, HOW to authenticate: which path,
which credential field (email vs username vs ...), and where the session token lives in the JSON
response — by performing a REAL, identity-proven login with the user-supplied credentials. No LLM.

The non-negotiable precision gate (from adversarial review): a discovered shape is only returned
once we PROVE the token authenticates as OUR user — by decoding the JWT claims and finding the
login id in them (primary), or the login response body echoing the id (secondary). Without that,
discovery would accept guest sessions, doc placeholders, and wrong-identity tokens.

Scope of this slice: JSON-body tokens (JWT or a token-keyed opaque value), Bearer injection. Tokens
delivered via Set-Cookie / response headers, non-Bearer schemes, nested/multi-field login bodies,
and resource-id discovery (needed for IDOR on non-Juice apps) are honest follow-ups."""
from __future__ import annotations
import base64
import json
import re
from dataclasses import dataclass

COMMON_LOGIN_PATHS = (
    "/rest/user/login", "/api/login", "/login", "/auth/login", "/api/auth/login",
    "/users/v1/login", "/api/v1/login", "/api/users/login", "/session", "/api/session",
)
LOGIN_FIELDS = ("email", "username", "user", "login", "identifier")
PASSWORD_FIELD = "password"
TOKEN_KEYS = ("token", "access_token", "auth_token", "accesstoken", "jwt", "id_token",
              "session", "session_token", "sessiontoken")
OWNED_ID_KEYS = ("bid", "basketid", "basket_id", "id", "userid", "user_id")
LOCKOUT_STATUS = (423, 429)
_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


@dataclass(frozen=True)
class LoginShape:
    path: str
    login_field: str
    token_path: tuple
    password_field: str = PASSWORD_FIELD
    auth_mode: str = "bearer"   # how to inject the token downstream (slice 1: Bearer only)


def _decode_jwt_claims(token):
    """Decode (NOT verify) a JWT's payload segment. Returns the claims dict, or None."""
    try:
        parts = str(token).split(".")
        if len(parts) != 3:
            return None
        seg = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(seg).decode("utf-8", "replace"))
    except Exception:
        return None


def _walk(obj, path=()):
    """Yield (path_tuple, scalar_value) for every leaf in a parsed JSON structure."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, path + (i,))
    else:
        yield path, obj


def _find_token(data):
    """Locate the session token: a JWT-shaped value first (strongest), else a long string under a
    token-ish key. Returns (path_tuple, value) or None."""
    for path, val in _walk(data):
        if isinstance(val, str) and _JWT_RE.match(val):
            return path, val
    for path, val in _walk(data):
        if (isinstance(val, str) and len(val) >= 20 and path
                and str(path[-1]).lower() in TOKEN_KEYS):
            return path, val
    return None


def _identity_match(container, lid):
    """True if the login id appears as an EXACT scalar value anywhere in a parsed JSON structure —
    not as a substring. Substring matching would accept an echoed id inside a longer error string
    ("invalid password for alice@x") or a coincidental claim ("id" inside "bid"); exact value
    equality pins it to a real identity field."""
    for _path, val in _walk(container):
        if isinstance(val, str) and val.strip().lower() == lid:
            return True
    return False


def _identity_proven(token, login_id, login_body):
    """Prove the token authenticates as OUR user: the login id is an EXACT value in the JWT claims
    (primary) or in the parsed JSON login body (secondary). Exact-value matching (not substring)
    rejects guest / wrong-identity tokens and failed-login bodies that merely echo the id inside an
    error message. The crux near-zero-FP gate; fails closed when neither proof holds."""
    lid = (login_id or "").strip().lower()
    if not lid:
        return False
    claims = _decode_jwt_claims(token)
    if claims is not None and _identity_match(claims, lid):
        return True
    try:
        body = json.loads(login_body) if isinstance(login_body, str) else login_body
    except Exception:
        return False
    return _identity_match(body, lid)


def _find_owned_id(data):
    """Best-effort: the user's own resource id from the login response (Juice Shop's basket id),
    so the two-user IDOR flow keeps working. None when the response carries no such id."""
    seen = {}
    for path, val in _walk(data):
        if isinstance(val, bool):
            continue
        if isinstance(val, int) and path:
            key = str(path[-1]).lower()
            if key in OWNED_ID_KEYS:
                seen.setdefault(key, val)
    for key in OWNED_ID_KEYS:
        if key in seen:
            return seen[key]
    return None


def discover_login(base_url, login_id, password, post, *,
                   paths=COMMON_LOGIN_PATHS, fields=LOGIN_FIELDS):
    """Discover the login shape by an identity-proven real login. post(url, json_body) ->
    (status, body). Scans path x field, continues past any candidate that fails the identity
    proof, aborts on a lockout signal, and returns the first proven LoginShape (or None)."""
    base = base_url.rstrip("/")
    for path in paths:
        url = base + path
        for field in fields:
            try:
                status, body = post(url, {field: login_id, PASSWORD_FIELD: password})
            except Exception:
                continue
            if status in LOCKOUT_STATUS:
                return None
            if status != 200 or not body:
                continue
            try:
                data = json.loads(body)
            except Exception:
                continue
            found = _find_token(data)
            if not found:
                continue
            tpath, tval = found
            if _identity_proven(tval, login_id, body):
                return LoginShape(path=path, login_field=field, token_path=tpath)
    return None


def shape_login(base_url, login_id, password, post, shape):
    """Log in using a discovered shape. Returns (token, owned_id); (None, None) on failure or when
    the login is not identity-proven. owned_id is best-effort and does not gate the token (unlike the
    Juice-Shop login_session). The identity proof is re-run here so EVERY bound role (attacker AND
    victim) is a confirmed real login — not just the one credential discover_login proved."""
    base = base_url.rstrip("/")
    try:
        status, body = post(base + shape.path,
                            {shape.login_field: login_id, shape.password_field: password})
    except Exception:
        return None, None
    if status != 200 or not body:
        return None, None
    try:
        data = json.loads(body)
    except Exception:
        return None, None
    tok = data
    try:
        for key in shape.token_path:
            tok = tok[key]
    except Exception:
        return None, None
    token = str(tok).strip() or None
    if token is None or not _identity_proven(token, login_id, body):
        return None, None       # never bind a role on an unproven (guest / wrong-creds) session
    return token, _find_owned_id(data)
