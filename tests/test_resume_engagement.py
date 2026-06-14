import json
from datetime import datetime
from ronin.orchestrator import orchestrate, resume_engagement, EngagementResult
from ronin.objective import Objective
from ronin.finding import Finding
from ronin.engagement import validate_engagement
from ronin.inference import FakeClient
from ronin.runner import FakeRunner, ExecResult
from ronin.results import ResultStore, results_path

NOW = datetime(2026, 1, 1)


def make_eng(tmp_path, **over):
    d = {
        "id": "e1", "name": "n", "mode": "client",
        "scope": {"in": ["127.0.0.1"], "exclude": []},
        "roe": {"allowed_actions": ["passive", "active-scan", "exploit"], "windows": []},
        "autonomy": "action-gated", "env": {"kind": "local"},
        "audit_log": str(tmp_path / "audit" / "e1.jsonl"), "state": "active",
    }
    d.update(over)
    return validate_engagement(d)


def _plan(objs):
    return json.dumps({"objectives": [{"objective": o, "target": t} for o, t in objs]})


def _replan(done, objs=(), reason="r"):
    return json.dumps({"done": done, "reason": reason,
                       "next_objectives": [{"objective": o, "target": t} for o, t in objs]})


def _ex_action(tool, command, target, cls):
    return json.dumps({"action": {"tool": tool, "command": command, "target": target,
                                  "declared_class": cls, "why": "x"}})


def _ex_done(findings):
    return json.dumps({"done": True, "findings": findings})


def _paused_prior(tmp_path, eng):
    planner = FakeClient([_plan([("exploit web", "127.0.0.1")])])
    executor = FakeClient([_ex_action("sqlmap", "sqlmap -u http://127.0.0.1", "127.0.0.1", "exploit")])
    prior = orchestrate(eng, goal="assess 127.0.0.1", planner_client=planner,
                        executor_client=executor, runner=FakeRunner(), now=NOW,
                        max_objectives=3, engagement_path=str(tmp_path / "e1.yaml"))
    assert len(prior.paused) == 1
    return prior


def test_orchestrate_persists_goal_in_result(tmp_path):
    eng = make_eng(tmp_path)
    prior = _paused_prior(tmp_path, eng)
    assert prior.goal == "assess 127.0.0.1"


def test_resume_completes_approved_objective(tmp_path):
    eng = make_eng(tmp_path)
    prior = _paused_prior(tmp_path, eng)
    pid = prior.paused[0]["pending_id"]
    ResultStore(results_path(eng)).put(id=pid, command="sqlmap -u http://127.0.0.1",
                                       output="1 injectable param", exit_code=0)
    rexec = FakeClient([_ex_done([{"title": "SQLi", "severity": "high", "evidence": "injectable",
                                   "tool": "sqlmap", "command": "sqlmap -u http://127.0.0.1"}])])
    rplan = FakeClient([_replan(True, [], "goal met")])
    res = resume_engagement(eng, prior, planner_client=rplan, executor_client=rexec,
                            runner=FakeRunner(), now=NOW, max_objectives=3)
    assert res.status == "completed"
    assert any(f.title == "SQLi" for f in res.findings)
    assert res.paused == []
    assert len(res.objectives_run) == len(prior.objectives_run)


def test_resume_continues_loop_with_followup(tmp_path):
    eng = make_eng(tmp_path)
    prior = _paused_prior(tmp_path, eng)
    pid = prior.paused[0]["pending_id"]
    ResultStore(results_path(eng)).put(id=pid, command="sqlmap -u http://127.0.0.1",
                                       output="injectable", exit_code=0)
    rexec = FakeClient([
        _ex_done([]),
        _ex_action("nmap", "nmap -sV 127.0.0.1", "127.0.0.1", "active-scan"),
        _ex_done([{"title": "nginx", "severity": "info", "evidence": "80", "tool": "nmap",
                   "command": "nmap -sV 127.0.0.1"}]),
    ])
    rplan = FakeClient([
        _replan(False, [("scan web", "127.0.0.1")], "chase the web service"),
        _replan(True, [], "done"),
    ])
    runner = FakeRunner({"nmap -sV 127.0.0.1": ExecResult("nginx", 0, 0.1, False)})
    res = resume_engagement(eng, prior, planner_client=rplan, executor_client=rexec,
                            runner=runner, now=NOW, max_objectives=5)
    assert res.status == "completed"
    assert any(f.title == "nginx" for f in res.findings)
    assert len(res.objectives_run) == len(prior.objectives_run) + 1


def test_not_yet_approved_stays_paused(tmp_path):
    eng = make_eng(tmp_path)
    prior = _paused_prior(tmp_path, eng)
    res = resume_engagement(eng, prior, planner_client=FakeClient(_replan(True)),
                            executor_client=FakeClient(_ex_done([])), runner=FakeRunner(),
                            now=NOW, max_objectives=3)
    assert len(res.paused) == 1
    assert res.paused[0]["pending_id"] == prior.paused[0]["pending_id"]


def test_resumed_objective_can_repause(tmp_path):
    eng = make_eng(tmp_path)
    prior = _paused_prior(tmp_path, eng)
    pid = prior.paused[0]["pending_id"]
    ResultStore(results_path(eng)).put(id=pid, command="sqlmap -u http://127.0.0.1",
                                       output="injectable", exit_code=0)
    rexec = FakeClient([_ex_action("hydra", "hydra ssh://127.0.0.1", "127.0.0.1", "exploit")])
    rplan = FakeClient([_replan(True, [], "done")])
    res = resume_engagement(eng, prior, planner_client=rplan, executor_client=rexec,
                            runner=FakeRunner(), now=NOW, max_objectives=3)
    assert len(res.paused) == 1
    assert res.paused[0]["pending_id"] != pid
