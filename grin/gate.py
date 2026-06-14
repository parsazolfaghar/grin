"""The gate: maps (resolved class, autonomy mode) -> 'run' (execute now) or
'pending' (hold for human approve/deny). Pure; fail-closed on unknown mode."""

INTRUSIVE = {"exploit", "post-exploit"}


def gate(resolved_class: str, autonomy: str, approved_phases=()) -> str:
    if autonomy == "autonomous":
        return "run"
    if autonomy == "action-gated":
        return "pending" if resolved_class in INTRUSIVE else "run"
    if autonomy == "phase-gated":
        if resolved_class not in INTRUSIVE:
            return "run"
        return "run" if resolved_class in set(approved_phases) else "pending"
    return "pending"   # unknown mode -> fail closed
