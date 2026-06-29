#!/usr/bin/env python3
"""bac-probe — deterministic broken-access-control detector for assessment mode.

Requests a list of sensitive candidate paths as an UNAUTHENTICATED client and reports the ones
that return real content without auth. Two precision guards, because the bench's headline metric
is precision (a false report to a real owner is the cardinal sin):

  1. **Sensitive-surface allowlist** — only paths that *should* be access-controlled are flagged
     (an open `/main.js` is not a finding).
  2. **Baseline diff** — a SPA (Angular/React) serves the SAME shell body for every unmatched
     route, so a 200 whose body equals the root `/` body is the shell, NOT exposed content.

Output is `HIT <path> <status> <reason>` lines, parsed by grin.extractors into Findings with
vuln_class=broken-access-control and the path as location."""
from __future__ import annotations
import argparse
import re

# Paths that should normally require authorization. A 200 with real content here is suspicious.
SENSITIVE = [
    re.compile(r"^/ftp(/|$)"), re.compile(r"^/admin"), re.compile(r"^/administration"),
    re.compile(r"\.git(/|$)"), re.compile(r"\.env$"), re.compile(r"\.bak$"),
    re.compile(r"^/backup"), re.compile(r"^/api/users"), re.compile(r"^/rest/admin"),
    re.compile(r"^/server-status"), re.compile(r"^/config(/|\.|$)"),
]

DEFAULT_PATHS = [
    "/ftp/", "/ftp/legal.md", "/ftp/acquisitions.md", "/ftp/package.json.bak",
    "/admin", "/administration", "/.git/config", "/.env", "/backup",
    "/api/users", "/rest/admin", "/server-status", "/config.json",
]


def _is_sensitive(path: str) -> bool:
    return any(rx.search(path) for rx in SENSITIVE)


def _is_hit(path, status, body, baseline):
    if status != 200:
        return False, ""
    body = body or ""
    if not body.strip():
        return False, ""
    if baseline is not None and body == baseline:
        return False, "spa-shell"          # same as the catch-all SPA page, not real content
    if not _is_sensitive(path):
        return False, ""
    return True, "sensitive content served without authentication"


def probe(base_url: str, fetch, paths=None):
    """fetch(url) -> (status:int, body:str). Returns a list of hit dicts {path,status,reason}."""
    base = base_url.rstrip("/")
    paths = paths if paths is not None else DEFAULT_PATHS
    try:
        _, baseline = fetch(base + "/")
    except Exception:
        baseline = None
    hits = []
    for p in paths:
        try:
            status, body = fetch(base + p)
        except Exception:
            continue
        ok, reason = _is_hit(p, status, body, baseline)
        if ok:
            hits.append({"path": p, "status": status, "reason": reason})
    # Dedup: a bare directory (path ending '/') and the files under it are the SAME exposure.
    # When concrete files are found, drop the directory hit so we report the specific resources
    # once rather than the same finding twice.
    paths = {h["path"] for h in hits}
    return [h for h in hits if not (h["path"].endswith("/")
            and any(o != h["path"] and o.startswith(h["path"]) for o in paths))]


def _urllib_fetch(url):
    import urllib.request
    try:
        r = urllib.request.urlopen(url, timeout=8)
        return r.status, r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


def main(argv=None, fetch=None, paths=None) -> int:
    ap = argparse.ArgumentParser(prog="bac-probe",
                                 description="Unauthenticated broken-access-control probe")
    ap.add_argument("--url", required=True)
    ap.add_argument("--paths", default=None,
                    help="comma-separated paths to probe (default: built-in sensitive set)")
    a = ap.parse_args(argv)
    plist = paths if paths is not None else (a.paths.split(",") if a.paths else None)
    hits = probe(a.url, fetch or _urllib_fetch, plist)
    print(f"bac-probe {a.url} (unauthenticated) — {len(hits)} finding(s)")
    for h in hits:
        print(f"HIT {h['path']} {h['status']} {h['reason']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
