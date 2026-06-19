"""Interactive tool driving.

grin's executor runs one-shot commands, so tools that need a live session — msfconsole, meterpreter,
interactive sqlmap, evil-winrm, an ssh shell, a C2 client — were out of reach. This drives them like a
human at the keyboard: spawn the tool, watch for the prompt it's waiting at, then feed the next step,
auto-answering routine confirmations (and injecting a known credential at password prompts).

Inspired by Decepticon's tmux/prompt-detection approach; implemented with pexpect for portability and
so the prompt logic (the part that matters) is pure + unit-testable. The session itself is thin I/O
and is live-validated against real tools on the rig.

Safety: auto-answers only cover routine confirmations and NEVER fabricate credentials — password/sudo
prompts are answered only from a caller-supplied `secrets` map, else the session stops. This stays
within grin's fail-closed posture: no blind "yes" to a tool's safer default.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# (kind, regex) checked against the TAIL of the accumulated output. Order = priority (first match wins),
# so specific tool prompts beat the generic shell prompt.
_PROMPTS: list[tuple[str, re.Pattern]] = [
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

# Routine confirmations grin will answer on its own. Password/sudo are deliberately absent — those
# must come from a caller-supplied secret, never invented.
_AUTO: dict[str, str] = {
    "ssh_fingerprint": "yes",       # accept the host key in an authorized engagement
    "yn_default_yes": "Y",          # proceed when the tool already recommends yes (e.g. sqlmap)
    "yn_default_no": "n",           # respect the tool's safer default
    "yes_no": "yes",                # a bare [y/n] in an offensive flow: proceed
    "pager": "q",                   # quit pagers so the session never hangs
}


def detect_prompt(buf: str) -> str | None:
    """Which interactive prompt (if any) `buf` is currently waiting at. Pure — this is the core that
    decides when to feed the next step."""
    tail = buf[-500:]
    for kind, rx in _PROMPTS:
        if rx.search(tail):
            return kind
    return None


def auto_answer(kind: str | None) -> str | None:
    """Safe canned answer for a routine confirmation prompt, or None if grin shouldn't answer it on
    its own (password/sudo/unknown)."""
    if kind is None:
        return None
    return _AUTO.get(kind)


@dataclass
class SessionResult:
    transcript: str
    reason: str  # "script-complete" | "eof" | "need-credential" | "timeout"


class InteractiveSession:
    """Thin pexpect wrapper. Live-validated against real tools on the rig; the testable logic lives in
    detect_prompt/auto_answer above."""

    def __init__(self, cmd: str, *, timeout: int = 60, env: dict | None = None, cwd: str | None = None):
        import pexpect  # lazy: the module imports (and its pure fns test) without pexpect installed
        self._px = pexpect
        self.timeout = timeout
        self.transcript = ""
        self.child = pexpect.spawn(
            cmd, encoding="utf-8", timeout=timeout, env=env, cwd=cwd, echo=False, codec_errors="replace"
        )

    def pump(self, timeout: int) -> str:
        """Read output until the next prompt / quiet / EOF; append to the transcript. Returns the last
        detected prompt kind ("" for timeout/eof)."""
        patterns = [rx.pattern for _, rx in _PROMPTS] + [self._px.TIMEOUT, self._px.EOF]
        try:
            self.child.expect(patterns, timeout=timeout)
        except Exception:
            pass
        self.transcript += self.child.before or ""
        after = getattr(self.child, "after", "")
        if isinstance(after, str):
            self.transcript += after
        return detect_prompt(self.transcript) or ""

    def send(self, line: str) -> None:
        self.child.sendline(line)

    def close(self) -> None:
        try:
            self.child.close(force=True)
        except Exception:
            pass


def run_interactive(
    cmd: str,
    script: list[str],
    *,
    timeout: int = 60,
    step_timeout: int = 30,
    secrets: dict | None = None,
    env: dict | None = None,
) -> SessionResult:
    """Drive an interactive tool: spawn `cmd`, then for each step wait for the tool's prompt, auto-answer
    routine confirmations, inject credentials from `secrets` at password prompts, and send the next
    scripted line at a real command prompt. Returns the full transcript (evidence) + why it stopped."""
    sess = InteractiveSession(cmd, timeout=timeout, env=env)
    secrets = secrets or {}
    steps = list(script)
    i = 0
    reason = "script-complete"
    try:
        sess.pump(step_timeout)  # drain the banner to the first prompt
        guard = 0
        while guard < len(steps) + 50:  # bound: confirmations + scripted steps + slack
            guard += 1
            kind = detect_prompt(sess.transcript)
            if kind in ("password", "sudo"):
                cred = secrets.get(kind) or secrets.get("password")
                if cred is None:
                    reason = "need-credential"
                    break
                sess.send(cred)
                sess.pump(step_timeout)
                continue
            auto = auto_answer(kind)
            if auto is not None:
                sess.send(auto)
                sess.pump(step_timeout)
                continue
            if i < len(steps):
                sess.send(steps[i])
                i += 1
                sess.pump(step_timeout)
                continue
            break  # at a command prompt with no steps left
        if not sess.child.isalive():
            reason = "eof"
    finally:
        sess.close()
    return SessionResult(transcript=sess.transcript, reason=reason)
