"""Turn a parsed Intent into a real, scope-locked Engagement written to ~/.grin/engagements/. The
operator's verbatim prompt is recorded in the audit log as the authorization record. No new execution
path — the GUI then runs the written YAML through the existing start_engagement/orchestrator/spine."""
import json
import os
import re
from datetime import datetime

import yaml

from grin.engagement import load_engagement
from grin.intent import Intent
from grin.manual import allowed_actions_for
from grin.strength import strength_params

DEFAULT_ROOT = os.path.expanduser("~/.grin/engagements")
_SCHEME = re.compile(r'^[a-z]+://', re.I)


def normalize_target(token: str) -> str:
    """A URL collapses to its host (scope is host-level); IP/CIDR/hostnames pass through."""
    t = (token or "").strip()
    had_scheme = bool(_SCHEME.match(t))
    t = _SCHEME.sub("", t)          # strip scheme
    if had_scheme:
        t = t.split("/", 1)[0]      # strip URL path; leave CIDR notation intact
    return t


def _slug(s: str) -> str:
    return re.sub(r'[^a-z0-9]+', '-', s.lower()).strip('-') or "target"


def build_adhoc_engagement(intent: Intent, *, now: datetime,
                           operator: str, root: str = DEFAULT_ROOT, stealth: str = "off",
                           strength: str = "normal", tool_acquire: str = "ask"):
    if not intent.targets:
        raise ValueError("no target in intent")
    target = normalize_target(intent.targets[0])
    stamp = now.strftime("%Y%m%d-%H%M%S")
    eid = f"adhoc-{_slug(target)}-{stamp}"
    os.makedirs(root, exist_ok=True)
    audit_log = os.path.join(root, f"{eid}.jsonl")
    actions = allowed_actions_for(intent.target_type)
    if strength_params(strength).recon_only:
        actions = ["passive", "active-scan"]
    doc = {
        "id": eid,
        "name": intent.goal or f"assessment of {target}",
        "mode": "adhoc",
        "scope": {"in": [target], "exclude": []},
        "roe": {"allowed_actions": actions},
        "autonomy": "autonomous",
        # adhoc engagements self-select tools per host (LocalRunner on a pentest box, else Docker
        # arsenal). The deployment profile still governs the brain; only tool execution auto-selects.
        "env": {"kind": "auto", "tool_acquire": tool_acquire,
                "tool_requests": os.path.join(root, f"{eid}.tools.json")},
        "audit_log": audit_log,
        "state": "active",
        # aggression follows the strength level (the bare-target heuristic is retired) so the
        # on-disk aggressive flag never disagrees with strength
        "aggressive": strength_params(strength).aggressive,
        "stealth": stealth,
        "strength": strength,
    }
    path = os.path.join(root, f"{eid}.yaml")
    with open(path, "w") as fh:
        yaml.safe_dump(doc, fh, sort_keys=False)
    with open(audit_log, "a") as fh:
        fh.write(json.dumps({
            "ts": now.isoformat(timespec="seconds"), "operator": operator,
            "event": "authorized", "prompt": intent.raw, "scope": [target]}) + "\n")
    return load_engagement(path), path
