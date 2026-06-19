"""Engagement playbooks — named templates that scaffold a ready-to-run engagement with sane
scope/ROE/autonomy/strength/stealth defaults for a common scenario, so an operator doesn't
hand-author the file (and doesn't accidentally grant exploit autonomy on a client asset). Swarm's
playbook idea, mapped onto grin's engagement schema. Pure: produces a dict that
`validate_engagement` accepts; no I/O. The CLI (`grin engagement new --playbook <name>`) writes it."""
from __future__ import annotations


class PlaybookError(ValueError):
    pass


# Each playbook is the policy half of an engagement (mode/roe/autonomy/strength/stealth). Identity
# (id/name/scope/env) is supplied per-run by build_engagement. Defaults are chosen conservatively:
# the broader the allowed_actions, the tighter the autonomy — except own-lab/ctf where full auto is
# the point. allowed_actions order mirrors ACTION_CLASSES so a validated engagement reads naturally.
PLAYBOOKS: dict[str, dict] = {
    "recon-only": {
        "mode": "own-lab",
        "allowed_actions": ["passive"],
        "autonomy": "action-gated",
        "strength": "recon",
        "stealth": "quiet",
        "blurb": "Passive recon only — no scanning, no exploitation. Every action gated.",
    },
    "external-asm": {
        "mode": "client",
        "allowed_actions": ["passive", "active-scan"],
        "autonomy": "action-gated",
        "strength": "normal",
        "stealth": "quiet",
        "blurb": "External attack-surface mapping — passive + active scanning, no exploitation, "
                 "quiet, every action gated. Safe default for a client perimeter sweep.",
    },
    "internal-network": {
        "mode": "client",
        "allowed_actions": ["passive", "active-scan", "exploit", "post-exploit"],
        "autonomy": "phase-gated",
        "strength": "normal",
        "stealth": "off",
        "blurb": "Internal network pentest — full kill chain, but exploitation/post-exploitation "
                 "open per-phase only after the operator approves that phase.",
    },
    "bug-bounty": {
        "mode": "adhoc",
        "allowed_actions": ["passive", "active-scan", "exploit"],
        "autonomy": "action-gated",
        "strength": "normal",
        "stealth": "quiet",
        "blurb": "Bug-bounty target — scan + exploit to prove a finding, no post-exploitation, "
                 "quiet to respect program rules, every action gated.",
    },
    "ctf-solver": {
        "mode": "own-lab",
        "allowed_actions": ["passive", "active-scan", "exploit", "post-exploit"],
        "autonomy": "autonomous",
        "strength": "aggressive",
        "stealth": "off",
        "blurb": "CTF / own lab — full auto, full kill chain, aggressive. For boxes you own.",
    },
}


def playbook_names() -> list[str]:
    return sorted(PLAYBOOKS)


def build_engagement(playbook: str, *, eid: str, name: str, scope_in,
                     scope_exclude=(), env: dict | None = None,
                     audit_dir: str = "./audit") -> dict:
    """Materialize a playbook into a full engagement dict (passes validate_engagement). Identity
    (eid/name/scope/env) is per-run; the playbook supplies the policy."""
    pb = PLAYBOOKS.get(playbook)
    if pb is None:
        raise PlaybookError(
            f"unknown playbook {playbook!r}; choose one of {', '.join(playbook_names())}")
    return {
        "id": eid,
        "name": name,
        "mode": pb["mode"],
        "scope": {"in": list(scope_in), "exclude": list(scope_exclude)},
        "roe": {"allowed_actions": list(pb["allowed_actions"])},
        "autonomy": pb["autonomy"],
        "strength": pb["strength"],
        "stealth": pb["stealth"],
        "env": dict(env) if env else {"kind": "local"},
        "audit_log": f"{audit_dir.rstrip('/')}/{eid}.jsonl",
        "state": "active",
    }
