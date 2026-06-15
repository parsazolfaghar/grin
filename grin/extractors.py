"""Deterministic output extractors — parse known-tool stdout and return Secrets.

extract(tool, command, output, target) -> list[Secret]

Rules:
- Never raises on any input (including None).
- Returns [] when nothing matches or output is empty.
- Deduplicates by (label, value) before returning.
"""
import re
from typing import List

from grin.secret import Secret

# ---------------------------------------------------------------------------
# Hydra credential extractor
# ---------------------------------------------------------------------------
# Matches lines like:
#   [22][ssh] host: 172.30.0.11   login: admin   password: password
#   [80][http-post-form] host: 10.0.0.1\tlogin:  user1  password:  pass1
_HYDRA_RE = re.compile(r"login:\s*(\S+)\s+password:\s*(\S+)", re.IGNORECASE)


def _extract_hydra(command: str, output: str, target: str) -> List[Secret]:
    seen: set[tuple[str, str]] = set()
    results: List[Secret] = []
    for line in output.splitlines():
        for m in _HYDRA_RE.finditer(line):
            login = m.group(1).strip()
            password = m.group(2).strip()
            key = (login, password)
            if key in seen:
                continue
            seen.add(key)
            results.append(Secret(
                label="SSH credentials",
                value=f"{login}:{password}",
                target=target,
                tool="hydra",
                command=command,
                context="Extracted from hydra output",
            ))
    return results


# ---------------------------------------------------------------------------
# Flag extractor
# ---------------------------------------------------------------------------
_FLAG_RE = re.compile(r"GRIN\{[0-9a-fA-F]+\}", re.ASCII)


def _extract_flags(tool: str, command: str, output: str, target: str) -> List[Secret]:
    seen: set[str] = set()
    results: List[Secret] = []
    for m in _FLAG_RE.finditer(output):
        flag = m.group(0)
        if flag in seen:
            continue
        seen.add(flag)
        results.append(Secret(
            label="flag",
            value=flag,
            target=target,
            tool=tool,
            command=command,
            context="Captured flag",
        ))
    return results


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def extract(tool: str, command: str, output: str, target: str) -> List[Secret]:
    """Extract secrets from tool output deterministically.

    Runs all registered extractors and returns a deduplicated list of Secrets.
    Never raises — returns [] on any error or empty/None input.
    """
    try:
        out = output or ""
        cmd = command or ""
        tgt = target or ""
        tl = tool or ""

        if not out:
            return []

        creds = _extract_hydra(cmd, out, tgt)
        flags = _extract_flags(tl, cmd, out, tgt)

        # Global dedup by (label, value) — in case two extractors somehow produce the same fact
        seen: set[tuple[str, str]] = set()
        combined: List[Secret] = []
        for sec in creds + flags:
            key = (sec.label, sec.value)
            if key not in seen:
                seen.add(key)
                combined.append(sec)

        return combined
    except Exception:
        return []
