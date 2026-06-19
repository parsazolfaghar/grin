#!/usr/bin/env python3
"""Interactive tool driver (`grin-shell`).

grin's executor runs one-shot commands, so tools that need a live session — msfconsole, meterpreter,
interactive sqlmap, evil-winrm, an ssh shell, ftp — were unreachable. This drives them like a human
at the keyboard in ONE invocation: spawn the tool, wait for the prompt it's stuck at, feed the next
scripted step, auto-answer routine confirmations, then return the full transcript as evidence. The
agent calls it as an ordinary command, so it still flows through the spine (authorize/gate/audit):

  grin-shell --cmd 'msfconsole -q' --step 'use exploit/...' --step 'run' --step 'exit'
  grin-shell --cmd 'ssh user@10.0.0.5' --step 'id' --step 'cat ~/flag.txt' --step 'exit'
  grin-shell --cmd 'sqlmap -u "http://t/?id=1"'          # auto-answers sqlmap's [Y/n] prompts

Inspired by Decepticon's tmux/prompt-detection; implemented with pexpect so it's portable and the
prompt logic stays pure. Self-contained (only pexpect beyond stdlib) so it runs on the Kali runner.

Safety / fail-closed: routine confirmations (ssh fingerprint, sqlmap [Y/n], pagers) are auto-answered;
password/sudo prompts are NEVER fabricated — they're answered only from --secret, else the session
stops with reason 'need-credential'. No blind "yes" to a tool's risky default."""
import argparse
import re
import sys
from dataclasses import dataclass

# (kind, regex) checked against the TAIL of accumulated output. Order = priority (first match wins),
# so specific tool prompts beat the generic shell prompt. Kept identical to grin/interactive.py.
_PROMPTS = [
    ("meterpreter", re.compile(r"meterpreter\s*>\s*$")),
    ("msf", re.compile(r"\bmsf\d*\s*(?:\x1b\[[0-9;]*m)?\s*>\s*$")),
    ("evil_winrm", re.compile(r"\*Evil-WinRM\*\s*PS\b[^\n]*>\s*$")),
    ("ssh_fingerprint", re.compile(r"\(yes/no(?:/\[fingerprint\])?\)\?\s*$", re.I)),
    ("sudo", re.compile(r"\[sudo\]\s+password[^\n]*:\s*$", re.I)),
    ("password", re.compile(r"(?:password|passphrase)[^\n]*:\s*$", re.I)),
    ("yn_default_yes", re.compile(r"\[Y/n\]\s*$")),
    ("yn_default_no", re.compile(r"\[y/N\]\s*$")),
    ("yes_no", re.compile(r"\[(?:y/n|yes/no)\][^\n]*$", re.I)),
    ("pager", re.compile(r"--More--|\(END\)\s*$|press\s+(?:enter|space)\b", re.I)),
    ("shell", re.compile(r"(?:^|\n)[^\n]{0,80}[#$]\s$")),
]

_AUTO = {
    "ssh_fingerprint": "yes",
    "yn_default_yes": "Y",
    "yn_default_no": "n",
    "yes_no": "yes",
    "pager": "q",
}


def detect_prompt(buf: str):
    tail = buf[-500:]
    for kind, rx in _PROMPTS:
        if rx.search(tail):
            return kind
    return None


def auto_answer(kind):
    if kind is None:
        return None
    return _AUTO.get(kind)


@dataclass
class SessionResult:
    transcript: str
    reason: str  # script-complete | eof | need-credential | timeout


def run_interactive(cmd, script, *, timeout=120, step_timeout=30, secrets=None):
    import pexpect  # the only non-stdlib dep; present on the Kali runner
    secrets = secrets or {}
    child = pexpect.spawn(cmd, encoding="utf-8", timeout=timeout, echo=False, codec_errors="replace")
    transcript = ""
    patterns = [rx.pattern for _, rx in _PROMPTS] + [pexpect.TIMEOUT, pexpect.EOF]

    def pump(t):
        nonlocal transcript
        try:
            child.expect(patterns, timeout=t)
        except Exception:
            pass
        transcript += child.before or ""
        after = getattr(child, "after", "")
        if isinstance(after, str):
            transcript += after

    steps = list(script)
    i = 0
    reason = "script-complete"
    try:
        pump(step_timeout)  # drain banner to first prompt
        guard = 0
        while guard < len(steps) + 50:
            guard += 1
            kind = detect_prompt(transcript)
            if kind in ("password", "sudo"):
                cred = secrets.get(kind) or secrets.get("password")
                if cred is None:
                    reason = "need-credential"
                    break
                child.sendline(cred)
                pump(step_timeout)
                continue
            auto = auto_answer(kind)
            if auto is not None:
                child.sendline(auto)
                pump(step_timeout)
                continue
            if i < len(steps):
                child.sendline(steps[i])
                i += 1
                pump(step_timeout)
                continue
            break
        if not child.isalive():
            reason = "eof"
    finally:
        try:
            child.close(force=True)
        except Exception:
            pass
    return SessionResult(transcript=transcript, reason=reason)


def _parse_secrets(items):
    out = {}
    for it in items or []:
        if "=" in it:
            k, v = it.split("=", 1)
            out[k.strip()] = v
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="grin-shell", description="Drive an interactive tool session")
    ap.add_argument("--cmd", required=True, help="the interactive tool to spawn")
    ap.add_argument("--step", action="append", default=[], help="a line to send at each prompt (repeatable)")
    ap.add_argument("--timeout", type=int, default=120, help="overall session timeout (s)")
    ap.add_argument("--step-timeout", type=int, default=30, dest="step_timeout",
                    help="per-step wait for the next prompt (s)")
    ap.add_argument("--secret", action="append", default=[], metavar="KIND=VALUE",
                    help="credential for a password/sudo prompt, e.g. password=hunter2 (repeatable)")
    a = ap.parse_args(argv)
    res = run_interactive(a.cmd, a.step, timeout=a.timeout, step_timeout=a.step_timeout,
                          secrets=_parse_secrets(a.secret))
    print(res.transcript)
    print(f"\n[grin-shell: session ended — {res.reason}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
