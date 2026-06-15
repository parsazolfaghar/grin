"""Aggressive exhaustive mode: a deterministic catalog sweep producing the coverage FLOOR of
objectives (one per applicable in-scope technique x target). Pure planning; the orchestrator runs
the objectives through the normal executor->spine. More attempts, never fewer guardrails."""
from grin.catalog import techniques_for
from grin.objective import Objective
from grin.services import extract_services

DEFAULT_AGGRESSIVE_BUDGET = {"max_objectives": 24, "max_steps": 80}


def sweep_objectives(catalog, scope_targets, services_by_target) -> list:
    """One Objective per (applicable technique x in-scope target). With no discovered services for
    a target, only 'always' techniques apply. Objective text leads with the ATT&CK id so the
    executor knows what to attempt and dedup is stable."""
    out = []
    for target in scope_targets:
        services = services_by_target.get(target, [])
        for t in techniques_for(catalog, services):
            text = f"[{t.id} {t.name}] attempt against {target}"
            out.append(Objective(objective=text, target=target, action_class=t.action_class))
    return out


def discovered_services(findings) -> dict:
    """Group open services discovered so far, parsed deterministically from nmap findings' evidence.
    Returns {target: [Service, ...]} deduped by port."""
    by_target = {}
    for f in findings:
        if getattr(f, "tool", "") != "nmap":
            continue
        for s in extract_services(getattr(f, "evidence", "") or ""):
            lst = by_target.setdefault(f.target, [])
            if all(x.port != s.port for x in lst):
                lst.append(s)
    return by_target
