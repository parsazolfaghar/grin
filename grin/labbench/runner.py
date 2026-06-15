"""Drive the one-role-at-a-time sweep: for each planned run, reset the lab, run a live engagement
(via the injected collect_fn -> RunArtifact), and score against the answer key. The live work lives
in the injected callables so this loop is pure and testable."""
from grin.lab.answers import by_id
from grin.labbench.matrix import plan_runs
from grin.labbench.scorers import RunArtifact, score_run


def run_sweep(matrix, targets, *, reset_fn, collect_fn):
    """Returns a list of (role, model, RunScore). `collect_fn(target, pins) -> RunArtifact`
    performs the live engagement; `reset_fn()` restores pristine lab state before each run."""
    target_ids = [t.id for t in targets]
    runs = plan_runs(matrix, target_ids)
    rows = []
    for spec in runs:
        target = by_id(targets, spec.target_id)
        reset_fn()
        try:
            artifact = collect_fn(target, spec.pins)
        except Exception:  # noqa: BLE001 - a dead model/run scores zero, sweep continues
            artifact = RunArtifact(target_id=spec.target_id, blob="", finding_text="",
                                   audit=[], transcript="", duration_s=0.0)
        rows.append((spec.role, spec.model, score_run(artifact, target)))
    return rows
