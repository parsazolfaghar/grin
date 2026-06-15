from grin.lab.answers import Target
from grin.labbench.matrix import Matrix
from grin.labbench.scorers import RunArtifact
from grin.labbench.runner import run_sweep


def _targets():
    return [Target("t1-ssh", "grin-lab-ssh", "172.30.0.11", "easy", [22],
                   "weak-credentials", ["ssh weak credentials"], "GRIN{a}", "flag-in-loot")]


def test_run_sweep_resets_then_runs_then_scores():
    m = Matrix(default_pins={"planner": "p", "recon": "r", "exploit": "e"},
               candidates={"exploit": ["e", "dolphin3:8b"]}, repeats=1)
    events = []

    def reset_fn():
        events.append("reset")

    def collect_fn(target, pins):
        events.append(("run", pins["exploit"], target.id))
        flag = target.flag if pins["exploit"] == "e" else "nope"
        return RunArtifact(target_id=target.id, blob=f"... {flag} ...",
                           finding_text="ssh weak credentials", audit=[],
                           transcript="ok", duration_s=3.0)

    rows = run_sweep(m, _targets(), reset_fn=reset_fn, collect_fn=collect_fn)
    assert len(rows) == 2
    assert events.count("reset") == 2
    role, model, score = rows[0]
    assert role == "exploit"
    captured = {(model, s.flag_captured) for _, model, s in rows}
    assert ("e", True) in captured and ("dolphin3:8b", False) in captured


def test_run_sweep_collect_error_scores_zero():
    m = Matrix(default_pins={"planner": "p", "recon": "r", "exploit": "e"},
               candidates={"exploit": ["e"]}, repeats=1)

    def boom(target, pins):
        raise RuntimeError("model died")

    rows = run_sweep(m, _targets(), reset_fn=lambda: None, collect_fn=boom)
    assert len(rows) == 1
    _, _, score = rows[0]
    assert score.flag_captured is False and score.findings_recall == 0.0
