import base64
import json

from grin.login_discovery import (
    discover_login, shape_login, LoginShape, _decode_jwt_claims, _find_token,
)


def _mkjwt(claims):
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return ".".join([b64({"alg": "HS256", "typ": "JWT"}), b64(claims), "sig"])


# --- the core: discover the shape by doing a REAL, identity-proven login ---

def test_discovers_juice_shop_shape():
    def post(url, body):
        if url.endswith("/rest/user/login") and "email" in body:
            jwt = _mkjwt({"id": 1, "email": body["email"]})
            return 200, json.dumps({"authentication": {"token": jwt, "bid": 6, "umail": body["email"]}})
        return 404, ""
    shape = discover_login("http://t", "me@x.io", "pw", post)
    assert isinstance(shape, LoginShape)
    assert shape.path == "/rest/user/login" and shape.login_field == "email"
    assert shape.token_path == ("authentication", "token")


def test_discovers_vampi_shape_username_field_auth_token():
    def post(url, body):
        if url.endswith("/users/v1/login") and "username" in body:
            return 200, json.dumps({"auth_token": _mkjwt({"sub": body["username"]}), "status": "success"})
        return 404, ""
    shape = discover_login("http://t", "grinatk", "pw", post)
    assert shape.path == "/users/v1/login" and shape.login_field == "username"
    assert shape.token_path == ("auth_token",)


def test_identity_proof_rejects_guest_session_token():
    # a real JWT, but it authenticates an anonymous/guest principal — NOT our user
    def post(url, body):
        if url.endswith("/session"):
            return 200, json.dumps({"token": _mkjwt({"sub": "anonymous"})})
        return 404, ""
    assert discover_login("http://t", "me@x.io", "pw", post) is None


def test_identity_proof_rejects_wrong_identity_token():
    def post(url, body):
        if url.endswith("/login"):
            return 200, json.dumps({"token": _mkjwt({"sub": "someoneelse@y.io"})})
        return 404, ""
    assert discover_login("http://t", "me@x.io", "pw", post) is None


def test_identity_proof_rejects_substring_only_match():
    # login id "adm" is a SUBSTRING of the JWT principal "admin" but is not our real identity; the
    # old substring proof would FALSE-accept it, exact-value matching rejects it
    def post(url, body):
        if url.endswith("/login"):
            return 200, json.dumps({"token": _mkjwt({"sub": "admin"})})
        return 404, ""
    assert discover_login("http://t", "adm", "pw", post) is None


def test_shape_login_rejects_unproven_session():
    # shape_login (used for BOTH attacker and victim) must re-prove identity: a 200 with a token for
    # a DIFFERENT principal (a failed/guest victim login) binds no role
    shape = LoginShape(path="/login", login_field="username", token_path=("token",))

    def post(url, body):
        return 200, json.dumps({"token": _mkjwt({"sub": "someoneelse"})})
    assert shape_login("http://t", "victim", "pw", post, shape) == (None, None)


def test_shape_login_returns_token_when_identity_proven():
    shape = LoginShape(path="/login", login_field="username", token_path=("token",))

    def post(url, body):
        return 200, json.dumps({"token": _mkjwt({"sub": body["username"]}), "bid": 7})
    tok, owned = shape_login("http://t", "victim", "pw", post, shape)
    assert tok is not None and owned == 7


def test_identity_proven_via_response_body_for_opaque_token():
    # non-JWT opaque token under a token-ish key, identity echoed in the body -> proven
    def post(url, body):
        if url.endswith("/api/login") and "email" in body:
            return 200, json.dumps({"access_token": "o" * 40, "user": {"email": body["email"]}})
        return 404, ""
    shape = discover_login("http://t", "me@x.io", "pw", post)
    assert shape is not None and shape.token_path == ("access_token",)


def test_no_token_anywhere_returns_none():
    def post(url, body):
        if url.endswith("/login"):
            return 200, json.dumps({"csrf": "abc123", "ok": True})   # csrf is not a session token
        return 404, ""
    assert discover_login("http://t", "me@x.io", "pw", post) is None


def test_lockout_status_aborts_discovery():
    def post(url, body):
        return 429, "too many requests"
    assert discover_login("http://t", "me@x.io", "pw", post) is None


def test_decode_jwt_claims_roundtrip():
    tok = _mkjwt({"sub": "abc", "role": "user"})
    assert _decode_jwt_claims(tok) == {"sub": "abc", "role": "user"}
    assert _decode_jwt_claims("not-a-jwt") is None


def test_find_token_prefers_jwt_then_token_key():
    jwt = _mkjwt({"sub": "x"})
    assert _find_token({"a": {"token": jwt}}) == (("a", "token"), jwt)
    assert _find_token({"access_token": "o" * 25})[0] == ("access_token",)
    assert _find_token({"nope": "short"}) is None
