from ronin.report_store import result_path, save_result, load_result
from ronin.orchestrator import EngagementResult
from ronin.objective import Objective
from ronin.finding import Finding
from ronin.engagement import validate_engagement

ENG = {
    "id": "e1", "name": "n", "mode": "client",
    "scope": {"in": ["*.acme.test"]},
    "roe": {"allowed_actions": ["passive"]},
    "autonomy": "action-gated", "env": {"kind": "local"},
    "audit_log": "./audit/e1.jsonl", "state": "active",
}


def test_result_path_derives_from_audit_log():
    eng = validate_engagement(ENG)
    assert result_path(eng) == "./audit/e1.engagement.json"


def _sample_result():
    return EngagementResult(
        status="completed",
        findings=[Finding(title="SQLi", target="www.acme.test", severity="high",
                          evidence="injectable param", tool="sqlmap",
                          command="sqlmap -u ...", recommendation="parameterize")],
        objectives_run=[Objective("enumerate", "*.acme.test"),
                        Objective("scan web", "www.acme.test")],
        paused=[{"objective": Objective("exploit", "www.acme.test"),
                 "pending_id": "pid1", "journal": "/tmp/j.json"}],
        plan_log=[{"kind": "initial_plan", "objectives": [Objective("enumerate", "*.acme.test")]},
                  {"kind": "replan", "done": True, "reason": "goal met",
                   "objectives": []}],
    )


def test_save_and_load_roundtrip(tmp_path):
    path = str(tmp_path / "e1.engagement.json")
    save_result(path, _sample_result())
    loaded = load_result(path)

    assert loaded.status == "completed"
    assert loaded.findings == [Finding(title="SQLi", target="www.acme.test", severity="high",
                                       evidence="injectable param", tool="sqlmap",
                                       command="sqlmap -u ...", recommendation="parameterize")]
    assert loaded.objectives_run == [Objective("enumerate", "*.acme.test"),
                                     Objective("scan web", "www.acme.test")]
    assert loaded.paused[0]["objective"] == Objective("exploit", "www.acme.test")
    assert loaded.paused[0]["pending_id"] == "pid1"
    assert loaded.plan_log[0]["objectives"] == [Objective("enumerate", "*.acme.test")]
    assert loaded.plan_log[1]["done"] is True
    assert loaded.plan_log[1]["reason"] == "goal met"


def test_load_missing_file_raises(tmp_path):
    import pytest
    with pytest.raises(FileNotFoundError):
        load_result(str(tmp_path / "nope.json"))


def test_goal_roundtrips(tmp_path):
    from ronin.report_store import result_path, save_result, load_result
    from ronin.orchestrator import EngagementResult
    path = str(tmp_path / "e.engagement.json")
    save_result(path, EngagementResult(status="completed", goal="assess the network"))
    assert load_result(path).goal == "assess the network"


def test_load_defaults_goal_when_absent(tmp_path):
    import json
    from pathlib import Path
    from ronin.report_store import load_result
    path = str(tmp_path / "old.engagement.json")
    Path(path).write_text(json.dumps({"status": "completed", "findings": [],
                                      "objectives_run": [], "paused": [], "plan_log": []}))
    assert load_result(path).goal == ""
