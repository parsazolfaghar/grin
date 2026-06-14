import json
from datetime import datetime
from ronin.executor import execute_task
from ronin.engagement import validate_engagement
from ronin.inference import FakeClient
from ronin.runner import FakeRunner, ExecResult

NOW = datetime(2026, 1, 1)


def make_eng(tmp_path, **over):
    d = {
        "id": "e1", "name": "n", "mode": "own-lab",
        "scope": {"in": ["127.0.0.1"], "exclude": []},
        "roe": {"allowed_actions": ["passive", "active-scan"], "windows": []},
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


def _finding(title):
    return {"title": title, "severity": "info", "evidence": "e", "tool": "nmap", "command": "c"}


def test_fabricated_finish_rejected_then_corrected(tmp_path):
    eng = make_eng(tmp_path)
    client = FakeClient([
        _done([_finding("fabricated")]),
        _action("nmap", "nmap -sV 127.0.0.1", "127.0.0.1", "active-scan"),
        _done([_finding("port 80 open")]),
    ])
    runner = FakeRunner({"nmap -sV 127.0.0.1": ExecResult("80 open", 0, 0.1, False)})
    res = execute_task(eng, objective="o", target="127.0.0.1", client=client, runner=runner,
                       now=NOW, max_steps=6)
    assert res.status == "completed"
    assert [f.title for f in res.findings] == ["port 80 open"]
    assert any(s.decision == "no_evidence" for s in res.journal.steps)
    assert any(s.decision == "executed" for s in res.journal.steps)


def test_empty_findings_done_accepted_with_nothing_run(tmp_path):
    eng = make_eng(tmp_path)
    res = execute_task(eng, objective="o", target="127.0.0.1", client=FakeClient(_done([])),
                       runner=FakeRunner(), now=NOW, max_steps=4)
    assert res.status == "completed"
    assert res.findings == []
    assert not any(s.decision == "no_evidence" for s in res.journal.steps)


def test_persistent_fabrication_exhausts_with_no_findings(tmp_path):
    eng = make_eng(tmp_path)
    client = FakeClient(_done([_finding("fake")]))
    res = execute_task(eng, objective="o", target="127.0.0.1", client=client, runner=FakeRunner(),
                       now=NOW, max_steps=3)
    assert res.status == "budget_exhausted"
    assert res.findings == []
    assert all(s.decision == "no_evidence" for s in res.journal.steps)


def test_refused_only_cannot_finish_with_findings(tmp_path):
    eng = make_eng(tmp_path)
    client = FakeClient([
        _action("nmap", "nmap evil.example.com", "evil.example.com", "active-scan"),
        _done([_finding("fake")]),
    ])
    res = execute_task(eng, objective="o", target="127.0.0.1", client=client, runner=FakeRunner(),
                       now=NOW, max_steps=3)
    assert res.status == "budget_exhausted"
    assert res.findings == []
    assert not any(s.decision == "executed" for s in res.journal.steps)
