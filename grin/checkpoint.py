"""Pure helpers for aggressive capture checkpoints: detect a freshly captured flag and route the
remaining objective queue per the operator's decision. No I/O; the orchestrator + app wire these in."""

CHECKPOINT_DECISIONS = ("sweep", "focus", "next", "stop")


def new_flags(secrets, already) -> list:
    """Flag values (Secret.label == 'flag') in `secrets` not in the `already` set, in order."""
    out = []
    for s in secrets:
        if getattr(s, "label", "") == "flag" and s.value not in already and s.value not in out:
            out.append(s.value)
    return out


def route_queue(decision: str, queue: list, target: str):
    """Return (new_queue, focus_target, stop) for a checkpoint decision. Unknown -> 'sweep'
    (fail-open: never silently ends a run)."""
    if decision == "focus":
        return [o for o in queue if o.target == target], target, False
    if decision == "next":
        return [o for o in queue if o.target != target], None, False
    if decision == "stop":
        return [], None, True
    return queue, None, False   # sweep / unknown
