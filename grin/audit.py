"""Append-only JSONL audit trail — the engagement's evidence log. One line per
action (authorized, refused, gated-resolved). Never rewritten."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def result_digest(output: str) -> str:
    return "sha256:" + hashlib.sha256((output or "").encode("utf-8", "replace")).hexdigest()


def audit(path, *, engagement: str, target: str, tool: str, command: str,
          action_class: str, decision: str, gated: bool, approved_by=None,
          exit_code=None, result_digest=None, duration_s=None, reason=None,
          stealth=None) -> dict:
    """Append exactly one audit line and return the record. Fields beyond the core
    set (reason/exit_code/...) are included only when provided."""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "engagement": engagement,
        "target": target,
        "tool": tool,
        "command": command,
        "action_class": action_class,
        "decision": decision,        # allow | refuse
        "gated": gated,
        "approved_by": approved_by,
    }
    if exit_code is not None:
        record["exit_code"] = exit_code
    if result_digest is not None:
        record["result_digest"] = result_digest
    if duration_s is not None:
        record["duration_s"] = round(duration_s, 3)
    if reason is not None:
        record["reason"] = reason
    if stealth is not None:
        record["stealth"] = stealth

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a") as f:
        f.write(json.dumps(record) + "\n")
    return record
