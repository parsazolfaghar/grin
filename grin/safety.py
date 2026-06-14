"""Self-protection guards (roadmap R3 — "secure" safe defaults).

These protect the OPERATOR's own box / runner host. Per the roadmap guiding principle they MUST
NOT censor or weaken offensive commands against an authorized target — the patterns below match
only unambiguous self-destruction of the local host/disk, never offensive tooling. Override-able
via GRIN_ALLOW_DESTRUCTIVE=1.
"""
import os
import re

# Narrow, high-confidence host/disk self-destruction patterns. None of these are offensive tools.
_SELF_DESTRUCT = [
    r"rm\s+-[a-z]*r[a-z]*\s+(/|/\*|~|\$home)(\s|/|$)",   # rm -rf on / /* ~ $HOME
    r"\bmkfs(\.\w+)?\b",                                  # format a filesystem
    r"\bdd\b.*\bof=/dev/",                                # overwrite a block device
    r">\s*/dev/(sd|nvme|hd|disk|mmcblk)",                 # redirect onto a block device
    r":\(\)\s*\{\s*:\s*\|\s*:?\s*&\s*\}\s*;\s*:",         # fork bomb
]
_RE = [re.compile(p, re.IGNORECASE) for p in _SELF_DESTRUCT]


def is_self_destructive(command: str) -> bool:
    """True if the command would destroy the operator's own host/disk (not a target action)."""
    c = command or ""
    return any(r.search(c) for r in _RE)


def destructive_allowed() -> bool:
    """Operator override to run a flagged command anyway."""
    return os.environ.get("GRIN_ALLOW_DESTRUCTIVE", "").lower() in ("1", "true", "yes")
