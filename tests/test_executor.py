import json
from datetime import datetime
from grin.executor import execute_task, resume_task, TaskResult
from grin.engagement import validate_engagement
from grin.inference import FakeClient
from grin.runner import FakeRunner, ExecResult
from grin.finding import Finding
from grin.results import ResultStore, results_path

NOW = datetime(2026, 1, 1)


def make_eng(tmp_path, **over):
    d = {
        "id": "e1", "name": "n", "mode": "client",
        "scope": {"in": ["*.acme.test", "203.0.113.0/24"], "exclude": ["vpn.acme.test"]},
        "roe": {"allowed_actions": ["passive", "active-scan", "exploit"], "windows": []},
        "autonomy": "autonomous", "env": {"kind": "local"},
        "audit_log": str(tmp_path / "audit" / "e1.jsonl"), "state": "active",
    }
    d.update(over)
    return validate_engagement(d)


def _action(tool, command, target, cls):
    return json.dumps({"action": {"tool": tool, "command": command, "target": target,
                                  "declared_class": cls, "why": "x"}})


def _done(findings):
    return json.dumps({"done": True, "findings": findings})


def test_runs_to_completion_with_findings(tmp_path):
    eng = make_eng(tmp_path)
    client = FakeClient([
        _action("nmap", "nmap -sV 203.0.113.7", "203.0.113.7", "active-scan"),
        _done([{"title": "nginx", "severity": "info", "evidence": "80 open",
                "tool": "nmap", "command": "nmap -sV 203.0.113.7"}]),
    ])
    runner = FakeRunner({"nmap -sV 203.0.113.7": ExecResult("80/tcp open http", 0, 0.5, False)})
    res = execute_task(eng, objective="find web", target="203.0.113.7", client=client,
                       runner=runner, now=NOW, max_steps=12)
    assert isinstance(res, TaskResult)
    assert res.status == "completed"
    assert res.findings == [Finding(title="nginx", target="203.0.113.7", severity="info",
                                    evidence="80 open", tool="nmap",
                                    command="nmap -sV 203.0.113.7")]
    assert res.journal.steps[0].decision == "executed"
    assert res.journal.steps[0].output == "80/tcp open http"


def test_refusal_is_fed_back_and_loop_continues(tmp_path):
    eng = make_eng(tmp_path)
    client = FakeClient([
        _action("nmap", "nmap evil.example.com", "evil.example.com", "active-scan"),
        _done([]),
    ])
    res = execute_task(eng, objective="o", target="203.0.113.7", client=client,
                       runner=FakeRunner(), now=NOW, max_steps=12)
    assert res.status == "completed"
    assert res.journal.steps[0].decision == "refused"
    assert "scope" in res.journal.steps[0].reason.lower()


def test_budget_exhausted(tmp_path):
    eng = make_eng(tmp_path)
    client = FakeClient(_action("nmap", "nmap -sV 203.0.113.7", "203.0.113.7", "active-scan"))
    runner = FakeRunner({"nmap -sV 203.0.113.7": ExecResult("ok", 0, 0.1, False)})
    res = execute_task(eng, objective="o", target="203.0.113.7", client=client,
                       runner=runner, now=NOW, max_steps=3)
    assert res.status == "budget_exhausted"
    assert len(res.journal.steps) == 3


def test_parse_miss_then_budget(tmp_path):
    eng = make_eng(tmp_path)
    client = FakeClient("I don't know")
    res = execute_task(eng, objective="o", target="203.0.113.7", client=client,
                       runner=FakeRunner(), now=NOW, max_steps=2)
    assert res.status == "budget_exhausted"
    assert all(s.decision == "parse_miss" for s in res.journal.steps)


def test_model_down_fails_closed(tmp_path):
    eng = make_eng(tmp_path)
    res = execute_task(eng, objective="o", target="203.0.113.7",
                       client=FakeClient("x", up=False), runner=FakeRunner(), now=NOW)
    assert res.status == "model_unavailable"
    assert res.journal.steps == []


def test_pause_on_gated_action(tmp_path):
    eng = make_eng(tmp_path, autonomy="action-gated")
    client = FakeClient(_action("sqlmap", "sqlmap -u http://www.acme.test", "www.acme.test",
                                "passive"))
    res = execute_task(eng, objective="o", target="www.acme.test", client=client,
                       runner=FakeRunner(), now=NOW, max_steps=12)
    assert res.status == "awaiting_approval"
    assert res.pending_id
    assert res.journal.awaiting_pending_id == res.pending_id


def test_resume_after_approval_completes(tmp_path):
    eng = make_eng(tmp_path, autonomy="action-gated")
    client = FakeClient(_action("sqlmap", "sqlmap -u http://www.acme.test", "www.acme.test",
                                "exploit"))
    paused = execute_task(eng, objective="o", target="www.acme.test", client=client,
                          runner=FakeRunner(), now=NOW, max_steps=12)
    assert paused.status == "awaiting_approval"
    ResultStore(results_path(eng)).put(id=paused.pending_id, command="sqlmap -u ...",
                                       output="1 injectable param", exit_code=0)
    client2 = FakeClient(_done([{"title": "SQLi", "severity": "high", "evidence": "injectable",
                                 "tool": "sqlmap", "command": "sqlmap -u ..."}]))
    res = resume_task(eng, paused.journal, client=client2, runner=FakeRunner(), now=NOW,
                      result_store=ResultStore(results_path(eng)))
    assert res.status == "completed"
    assert res.findings[0].severity == "high"
    assert any(s.decision == "executed" and s.output == "1 injectable param"
               for s in res.journal.steps)


def test_resume_before_approval_stays_awaiting(tmp_path):
    eng = make_eng(tmp_path, autonomy="action-gated")
    client = FakeClient(_action("sqlmap", "sqlmap -u http://www.acme.test", "www.acme.test",
                                "exploit"))
    paused = execute_task(eng, objective="o", target="www.acme.test", client=client,
                          runner=FakeRunner(), now=NOW, max_steps=12)
    res = resume_task(eng, paused.journal, client=FakeClient(_done([])), runner=FakeRunner(),
                      now=NOW, result_store=ResultStore(results_path(eng)))
    assert res.status == "awaiting_approval"


def test_resume_on_completed_journal_is_noop(tmp_path):
    eng = make_eng(tmp_path)
    client = FakeClient([
        _action("nmap", "nmap -sV 203.0.113.7", "203.0.113.7", "active-scan"),
        _done([{"title": "x", "severity": "info", "evidence": "e",
                "tool": "nmap", "command": "c"}]),
    ])
    runner = FakeRunner({"nmap -sV 203.0.113.7": ExecResult("ok", 0, 0.1, False)})
    done = execute_task(eng, objective="o", target="203.0.113.7", client=client,
                        runner=runner, now=NOW, max_steps=12)
    assert done.status == "completed"
    n_steps = len(done.journal.steps)
    # resuming a NON-awaiting (completed) journal must not run any new actions
    res = resume_task(eng, done.journal,
                      client=FakeClient(_action("nmap", "nmap x", "203.0.113.7", "active-scan")),
                      runner=runner, now=NOW, result_store=ResultStore(results_path(eng)))
    assert res.status == "completed"
    assert len(res.journal.steps) == n_steps     # unchanged — no new actions


def test_execute_task_returns_secrets(tmp_path):
    import json
    from datetime import datetime
    from grin.executor import execute_task
    from grin.engagement import validate_engagement
    from grin.inference import FakeClient
    from grin.runner import FakeRunner, ExecResult
    from grin.secret import Secret
    eng = validate_engagement({"id":"e1","name":"n","mode":"own-lab",
        "scope":{"in":["127.0.0.1"]},"roe":{"allowed_actions":["passive","active-scan"]},
        "autonomy":"autonomous","env":{"kind":"local"},
        "audit_log":str(tmp_path/"audit"/"e1.jsonl"),"state":"active"})
    client = FakeClient([
        json.dumps({"action":{"tool":"nmap","command":"nmap 127.0.0.1","target":"127.0.0.1","declared_class":"active-scan","why":"x"}}),
        json.dumps({"done":True,"findings":[],"secrets":[
            {"label":"SSH password","value":"root:toor","target":"127.0.0.1","tool":"nmap","command":"c","context":"ctx"}]}),
    ])
    runner = FakeRunner({"nmap 127.0.0.1": ExecResult("ok",0,0.1,False)})
    res = execute_task(eng, objective="o", target="127.0.0.1", client=client, runner=runner,
                       now=datetime(2026,1,1), max_steps=6)
    assert res.status == "completed"
    assert res.secrets == [Secret("SSH password","root:toor","127.0.0.1","nmap","c","ctx")]


def test_secrets_also_evidence_gated(tmp_path):
    import json
    from datetime import datetime
    from grin.executor import execute_task
    from grin.engagement import validate_engagement
    from grin.inference import FakeClient
    from grin.runner import FakeRunner
    eng = validate_engagement({"id":"e1","name":"n","mode":"own-lab",
        "scope":{"in":["127.0.0.1"]},"roe":{"allowed_actions":["passive","active-scan"]},
        "autonomy":"autonomous","env":{"kind":"local"},
        "audit_log":str(tmp_path/"audit"/"e1.jsonl"),"state":"active"})
    client = FakeClient(json.dumps({"done":True,"findings":[],"secrets":[
        {"label":"x","value":"y","target":"127.0.0.1","tool":"t","command":"c"}]}))
    res = execute_task(eng, objective="o", target="127.0.0.1", client=client, runner=FakeRunner(),
                       now=datetime(2026,1,1), max_steps=2)
    assert res.status == "budget_exhausted"
    assert res.secrets == []


def test_should_stop_halts_immediately(tmp_path):
    # operator hit Stop: execute_task bails before running any step
    eng = make_eng(tmp_path)
    client = FakeClient([_action("nmap", "nmap -sV 203.0.113.7", "203.0.113.7", "active-scan")])
    res = execute_task(eng, objective="scan", target="203.0.113.7", client=client,
                       runner=FakeRunner(), now=NOW, brain=None, should_stop=lambda: True)
    assert res.status == "completed"
    assert len([s for s in res.journal.steps if s.decision == "executed"]) == 0


def test_recon_loop_is_capped(tmp_path):
    # nmap re-run with different flags on the same host doesn't dedup — cap stops the re-scan spin
    eng = make_eng(tmp_path)
    client = FakeClient([
        _action("nmap", "nmap -sV 203.0.113.7", "203.0.113.7", "active-scan"),
        _action("nmap", "nmap -p- 203.0.113.7", "203.0.113.7", "active-scan"),
        _action("nmap", "nmap -p- -sV 203.0.113.7", "203.0.113.7", "active-scan"),
        _action("nmap", "nmap -p- -sC 203.0.113.7", "203.0.113.7", "active-scan"),
        _action("nmap", "nmap -A 203.0.113.7", "203.0.113.7", "active-scan"),
    ])
    res = execute_task(eng, objective="scan", target="203.0.113.7", client=client,
                       runner=FakeRunner(), now=NOW, brain=None)
    executed = [s for s in res.journal.steps if s.decision == "executed"]
    dups = [s for s in res.journal.steps if s.decision == "duplicate"]
    assert len(executed) <= 2          # recon capped at 2 nmap runs on the host
    assert len(dups) >= 1              # further nmap flagged as non-progress
