"""Per-target-type capability manual, derived purely from the ATT&CK catalog. Given a target type we
synthesize the services such a target typically exposes, then reuse catalog.techniques_for to list
every technique (and its tools) Grin can bring, grouped by tactic in kill-chain order. Also the single
source of truth for the ROE allowed_actions per target type."""
from dataclasses import dataclass, field

from grin.catalog import techniques_for
from grin.services import Service

_PROFILE_SERVICES = {
    "web-url": [Service(port=80, name="http"), Service(port=443, name="https")],
    "ip-host": [Service(port=22, name="ssh"), Service(port=80, name="http"),
                Service(port=443, name="https")],
    "cidr-network": [Service(port=22, name="ssh"), Service(port=80, name="http"),
                     Service(port=443, name="https")],
    "hostname": [Service(port=22, name="ssh"), Service(port=80, name="http"),
                 Service(port=443, name="https")],
    "unknown": [],
}

_ALLOWED = {
    "web-url": ["passive", "active-scan", "exploit", "post-exploit"],
    "ip-host": ["passive", "active-scan", "exploit", "post-exploit"],
    "cidr-network": ["passive", "active-scan", "exploit", "post-exploit"],
    "hostname": ["passive", "active-scan", "exploit", "post-exploit"],
    "unknown": ["passive", "active-scan"],
}

_HEADERS = {
    "web-url": "Web target — Grin can map the app, enumerate endpoints, and test auth and injection.",
    "ip-host": "IP host — Grin can scan services, brute-force logins, exploit, and post-exploit.",
    "cidr-network": "Network range — Grin can sweep hosts, find services, and exploit what it finds.",
    "hostname": "Host — Grin resolves it, scans services, and exploits exposed surfaces.",
    "unknown": "Unrecognized target — Grin will scan to discover what is reachable, then adapt.",
}

_TACTIC_ORDER = ["reconnaissance", "discovery", "initial-access", "execution",
                 "credential-access", "privilege-escalation", "lateral-movement",
                 "collection", "exfiltration"]


@dataclass(frozen=True)
class ManualSection:
    tactic: str
    items: list = field(default_factory=list)


@dataclass(frozen=True)
class Manual:
    target_type: str
    header: str
    sections: list = field(default_factory=list)


def allowed_actions_for(target_type: str) -> list:
    return list(_ALLOWED.get(target_type, _ALLOWED["unknown"]))


def header_for(target_type: str) -> str:
    return _HEADERS.get(target_type, _HEADERS["unknown"])


def _tactic_key(tactic: str) -> int:
    return _TACTIC_ORDER.index(tactic) if tactic in _TACTIC_ORDER else len(_TACTIC_ORDER)


def manual_for(target_type: str, catalog) -> Manual:
    services = _PROFILE_SERVICES.get(target_type, [])
    techs = techniques_for(catalog, services)
    by_tactic = {}
    for t in techs:
        label = f"{t.name} [{', '.join(t.tools)}]"
        by_tactic.setdefault(t.tactic, [])
        if label not in by_tactic[t.tactic]:
            by_tactic[t.tactic].append(label)
    sections = [ManualSection(tactic=tac, items=by_tactic[tac])
                for tac in sorted(by_tactic, key=_tactic_key)]
    return Manual(target_type=target_type, header=header_for(target_type), sections=sections)
