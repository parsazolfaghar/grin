#!/usr/bin/env python3
"""idor-probe — deterministic IDOR / broken-object-level-authorization detector.

The signal: an attacker (user A) requests a resource that belongs to a victim (user B) and gets
B's data back. Concretely — request B's resource URL with A's session and check whether the
response is a 200 that contains B's identifying marker (data only B should see). 401/403, an
empty body, or a body without the victim marker is NOT an IDOR.

The auth/session setup (logging in as two users, learning B's resource URL + marker) is the
harness's job; probe_idor is the pure comparison so it is fully testable. Precision guard: an
empty victim marker never fires (it would match every response)."""
from __future__ import annotations
import json


def authenticate(base_url, email, password, http_post,
                 login_path="/rest/user/login", token_path=("authentication", "token")):
    """Log in and return a session token, or None on failure.

    http_post(url, json_body) -> (status:int, body:str). login_path + token_path default to the
    Juice Shop shape but are parameters so the harness can target other apps. Fail-soft: any
    non-200, missing field, or unparseable body returns None rather than raising."""
    try:
        status, body = http_post(base_url.rstrip("/") + login_path,
                                 {"email": email, "password": password})
    except Exception:
        return None
    if status != 200:
        return None
    try:
        data = json.loads(body)
        for key in token_path:
            data = data[key]
        token = str(data).strip()
        return token or None
    except Exception:
        return None


def probe_idor(resource_urls, victim_marker: str, fetch_as_attacker):
    """fetch_as_attacker(url) -> (status:int, body:str), performed with the ATTACKER's session.

    Returns a list of hit dicts {url, status} for resources where the attacker received the
    victim's data."""
    marker = (victim_marker or "").strip()
    if not marker:
        return []   # never fire without a concrete victim marker
    hits = []
    for url in resource_urls:
        try:
            status, body = fetch_as_attacker(url)
        except Exception:
            continue
        if status == 200 and marker in (body or ""):
            hits.append({"url": url, "status": status})
    return hits


def _urllib_post(url, json_body):
    import json as _json
    import urllib.request
    data = _json.dumps(json_body).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=8)
        return r.status, r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


def _urllib_get_with_token(token):
    import urllib.request

    def fetch(url):
        req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
        try:
            r = urllib.request.urlopen(req, timeout=8)
            return r.status, r.read(65536).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, ""
        except Exception:
            return 0, ""
    return fetch


def main(argv=None, http_post=None, fetch_factory=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="idor-probe",
                                 description="Authenticated IDOR / broken-object-level-auth probe")
    ap.add_argument("--url", required=True, help="base URL")
    ap.add_argument("--attacker", required=True, help="attacker creds EMAIL:PASSWORD")
    ap.add_argument("--resources", required=True,
                    help="comma-separated victim resource URLs the attacker should NOT reach")
    ap.add_argument("--marker", required=True, help="victim data string proving cross-user access")
    a = ap.parse_args(argv)
    email, _, password = a.attacker.partition(":")
    token = authenticate(a.url, email, password, http_post or _urllib_post)
    if not token:
        print("idor-probe: attacker authentication failed")
        return 1
    fetch = (fetch_factory or _urllib_get_with_token)(token)
    resources = [r.strip() for r in a.resources.split(",") if r.strip()]
    hits = probe_idor(resources, a.marker, fetch)
    print(f"idor-probe {a.url} (as {email}) — {len(hits)} finding(s)")
    for h in hits:
        print(f"IDOR {h['url']} {h['status']} victim data reachable across users")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
