from grin.journal import Step, Journal, journal_path
from grin.finding import Finding
from grin.engagement import validate_engagement

ENG = {
    "id": "e1", "name": "n", "mode": "own-lab",
    "scope": {"in": ["10.0.0.0/24"]}, "roe": {"allowed_actions": ["active-scan"]},
    "autonomy": "autonomous", "env": {"kind": "local"},
    "audit_log": "./audit/e1.jsonl", "state": "active",
}


def test_journal_path_derives_from_audit_log_and_task_id():
    eng = validate_engagement(ENG)
    assert journal_path(eng, "task42") == "./audit/e1.task42.journal.json"


def test_add_step_and_render_history():
    j = Journal(task_id="t1", objective="find web", target="10.0.0.5",
                engagement_path="e.yaml", path="/tmp/j.json")
    j.add_step(Step(action={"tool": "nmap", "command": "nmap -sV 10.0.0.5"},
                    decision="executed", output="80/open tcp", exit_code=0))
    j.add_step(Step(action={"tool": "x", "command": "x evil"},
                    decision="refused", reason="out of scope"))
    h = j.render_history()
    assert "executed" in h and "nmap -sV 10.0.0.5" in h and "80/open" in h
    assert "refused" in h and "out of scope" in h


def test_render_history_empty_is_safe():
    j = Journal(task_id="t", objective="o", target="h", engagement_path="e", path="/tmp/x.json")
    assert isinstance(j.render_history(), str)   # no crash on empty history


def test_save_and_load_roundtrip(tmp_path):
    p = str(tmp_path / "j.json")
    j = Journal(task_id="t1", objective="o", target="10.0.0.5",
                engagement_path="e.yaml", path=p, max_steps=12)
    j.add_step(Step(action={"tool": "nmap", "command": "c"}, decision="pending",
                    pending_id="pid9"))
    j.awaiting_pending_id = "pid9"
    j.set_findings([Finding(title="t", target="10.0.0.5", severity="low", evidence="e",
                            tool="nmap", command="c")])
    j.save()

    loaded = Journal.load(p)
    assert loaded.objective == "o"
    assert loaded.max_steps == 12
    assert loaded.awaiting_pending_id == "pid9"
    assert loaded.steps[0].decision == "pending"
    assert loaded.steps[0].pending_id == "pid9"
    assert loaded.findings[0] == Finding(title="t", target="10.0.0.5", severity="low",
                                         evidence="e", tool="nmap", command="c")


def test_update_pending_result_marks_executed():
    j = Journal(task_id="t", objective="o", target="h", engagement_path="e", path="/tmp/x.json")
    j.add_step(Step(action={"tool": "sqlmap", "command": "sqlmap x"}, decision="pending",
                    pending_id="pid1"))
    j.awaiting_pending_id = "pid1"
    j.update_pending_result("pid1", "injection found", 0)
    assert j.steps[0].decision == "executed"
    assert j.steps[0].output == "injection found"
    assert j.awaiting_pending_id is None


def test_render_history_shows_no_evidence_nudge():
    from grin.journal import Journal, Step
    j = Journal(task_id="t", objective="o", target="h", engagement_path="e", path="/tmp/x.json")
    j.add_step(Step(action={}, decision="no_evidence"))
    assert "evidence" in j.render_history().lower()
