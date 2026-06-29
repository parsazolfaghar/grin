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


def login_session(base_url, email, password, http_post,
                  login_path="/rest/user/login",
                  token_path=("authentication", "token"),
                  id_path=("authentication", "bid")):
    """Like authenticate() but also returns the user's OWN resource id (the basket id for Juice
    Shop) so the two-user IDOR flow can have the attacker request the VICTIM's id. Returns
    (token, owned_id), or (None, None) on failure."""
    try:
        status, body = http_post(base_url.rstrip("/") + login_path,
                                 {"email": email, "password": password})
    except Exception:
        return None, None
    if status != 200:
        return None, None
    try:
        data = json.loads(body)
        tok = data
        for key in token_path:
            tok = tok[key]
        oid = data
        for key in id_path:
            oid = oid[key]
        token = str(tok).strip()
        return (token or None), oid
    except Exception:
        return None, None


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


def detect_crossuser_idor(victim_url, fetch_as_attacker, fetch_as_victim) -> bool:
    """Robust cross-user IDOR signal: the attacker requests the VICTIM's resource and receives the
    SAME bytes the victim sees for it (a 200). No fragile marker — if A's view of B's resource is
    byte-identical to B's own view, A accessed B's object. A 401/403, an empty victim body, or a
    different response (A's own resource / an error) is not an IDOR."""
    try:
        sa, ba = fetch_as_attacker(victim_url)
        _sv, bv = fetch_as_victim(victim_url)
    except Exception:
        return False
    return sa == 200 and bool((bv or "").strip()) and ba == bv


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
    # Two-user self-contained mode (preferred — the autonomous agent only needs the creds):
    ap.add_argument("--user-a", help="attacker creds EMAIL:PASSWORD")
    ap.add_argument("--user-b", help="victim creds EMAIL:PASSWORD (enables two-user IDOR mode)")
    ap.add_argument("--resource", help="victim resource template, e.g. /rest/basket/{id}")
    # Marker mode (when the victim resource URL + a marker are already known):
    ap.add_argument("--attacker", help="attacker creds EMAIL:PASSWORD (marker mode)")
    ap.add_argument("--resources", help="comma-separated victim resource URLs (marker mode)")
    ap.add_argument("--marker", help="victim data string proving cross-user access (marker mode)")
    a = ap.parse_args(argv)
    post = http_post or _urllib_post
    make_fetch = fetch_factory or _urllib_get_with_token

    if a.user_a and a.user_b and a.resource:
        ea, _, pa = a.user_a.partition(":")
        eb, _, pb = a.user_b.partition(":")
        tok_a, _ = login_session(a.url, ea, pa, post)
        tok_b, id_b = login_session(a.url, eb, pb, post)
        if not (tok_a and tok_b and id_b is not None):
            print("idor-probe: authentication failed")
            return 1
        victim_url = a.url.rstrip("/") + a.resource.replace("{id}", str(id_b))
        hit = detect_crossuser_idor(victim_url, make_fetch(tok_a), make_fetch(tok_b))
        print(f"idor-probe {a.url} (A={ea} vs B={eb}) — {1 if hit else 0} finding(s)")
        if hit:
            print(f"IDOR {victim_url} 200 cross-user object access "
                  "(attacker read the victim's resource)")
        return 0

    if a.attacker and a.resources and a.marker:
        email, _, password = a.attacker.partition(":")
        token = authenticate(a.url, email, password, post)
        if not token:
            print("idor-probe: attacker authentication failed")
            return 1
        fetch = make_fetch(token)
        resources = [r.strip() for r in a.resources.split(",") if r.strip()]
        hits = probe_idor(resources, a.marker, fetch)
        print(f"idor-probe {a.url} (as {email}) — {len(hits)} finding(s)")
        for h in hits:
            print(f"IDOR {h['url']} {h['status']} victim data reachable across users")
        return 0

    print("idor-probe: provide --user-a/--user-b/--resource (two-user mode) "
          "or --attacker/--resources/--marker (marker mode)")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
