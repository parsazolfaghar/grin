import json
from datetime import datetime
from ronin.spine import submit_action, approve_action, deny_action, Outcome
from ronin.engagement import validate_engagement, pending_path
from ronin.pending import PendingStore
from ronin.runner import FakeRunner, ExecResult

IN_WINDOW = datetime(2026, 6, 13, 20, 0)


def make_eng(tmp_path, **over):
    d = {
        "id": "e1", "name": "n", "mode": "client",
        "scope": {"in": ["*.acme.test", "203.0.113.0/24"], "exclude": ["vpn.acme.test"]},
        "roe": {"allowed_actions": ["passive", "active-scan", "exploit"],
                "windows": [{"start": "2026-06-13T18:00", "end": "2026-06-14T06:00"}]},
        "autonomy": "action-gated", "env": {"kind": "local"},
        "audit_log": str(tmp_path / "audit" / "e1.jsonl"), "state": "active",
    }
    d.update(over)
    return validate_engagement(d)


def _audit_lines(eng):
    try:
        return [json.loads(l) for l in open(eng.audit_log).read().splitlines()]
    except FileNotFoundError:
        return []


def test_allowed_nonintrusive_executes_and_audits_allow(tmp_path):
    eng = make_eng(tmp_path)
    runner = FakeRunner({"nmap -sV 203.0.113.7": ExecResult("PORT 80 open", 0, 1.2, False)})
    out = submit_action(eng, target="203.0.113.7", tool="nmap",
                        command="nmap -sV 203.0.113.7", declared_class="active-scan",
                        runner=runner, now=IN_WINDOW)
    assert isinstance(out, Outcome)
    assert out.status == "executed"
    assert out.result.output == "PORT 80 open"
    recs = _audit_lines(eng)
    assert len(recs) == 1
    assert recs[0]["decision"] == "allow"
    assert recs[0]["action_class"] == "active-scan"
    assert recs[0]["result_digest"].startswith("sha256:")


def test_out_of_scope_refused_and_audited_not_executed(tmp_path):
    eng = make_eng(tmp_path)
    runner = FakeRunner()
    out = submit_action(eng, target="evil.example.com", tool="nmap", command="nmap evil",
                        declared_class="active-scan", runner=runner, now=IN_WINDOW)
    assert out.status == "refused"
    recs = _audit_lines(eng)
    assert len(recs) == 1
    assert recs[0]["decision"] == "refuse"
    assert "scope" in recs[0]["reason"].lower()


def test_anti_spoof_mislabeled_exploit_is_gated(tmp_path):
    eng = make_eng(tmp_path)
    runner = FakeRunner()
    out = submit_action(eng, target="www.acme.test", tool="sqlmap",
                        command="sqlmap -u http://www.acme.test --batch",
                        declared_class="passive", runner=runner, now=IN_WINDOW)
    assert out.status == "pending"
    assert out.pending_id
    assert _audit_lines(eng) == []
    store = PendingStore(pending_path(eng))
    assert store.list()[0]["resolved_class"] == "exploit"


def test_disallowed_class_refused(tmp_path):
    eng = make_eng(tmp_path)
    out = submit_action(eng, target="www.acme.test", tool="mimikatz",
                        command="mimikatz", declared_class="post-exploit",
                        runner=FakeRunner(), now=IN_WINDOW)
    assert out.status == "refused"
    assert _audit_lines(eng)[0]["decision"] == "refuse"


def test_autonomous_runs_intrusive_immediately(tmp_path):
    eng = make_eng(tmp_path, autonomy="autonomous")
    runner = FakeRunner({"sqlmap -u x": ExecResult("injection found", 0, 2.0, False)})
    out = submit_action(eng, target="www.acme.test", tool="sqlmap", command="sqlmap -u x",
                        declared_class="exploit", runner=runner, now=IN_WINDOW)
    assert out.status == "executed"
    assert _audit_lines(eng)[0]["decision"] == "allow"


def test_approve_executes_and_records_approver(tmp_path):
    eng = make_eng(tmp_path)
    runner = FakeRunner({"sqlmap -u x": ExecResult("done", 0, 1.0, False)})
    pend = submit_action(eng, target="www.acme.test", tool="sqlmap", command="sqlmap -u x",
                         declared_class="exploit", runner=runner, now=IN_WINDOW)
    out = approve_action(eng, pend.pending_id, approver="operator", runner=runner, now=IN_WINDOW)
    assert out.status == "executed"
    rec = _audit_lines(eng)[0]
    assert rec["decision"] == "allow"
    assert rec["gated"] is True
    assert rec["approved_by"] == "operator"
    assert PendingStore(pending_path(eng)).list() == []


def test_deny_logs_refusal_with_approver(tmp_path):
    eng = make_eng(tmp_path)
    runner = FakeRunner()
    pend = submit_action(eng, target="www.acme.test", tool="hydra", command="hydra ...",
                         declared_class="exploit", runner=runner, now=IN_WINDOW)
    out = deny_action(eng, pend.pending_id, approver="operator")
    assert out.status == "refused"
    rec = _audit_lines(eng)[0]
    assert rec["decision"] == "refuse"
    assert rec["gated"] is True
    assert rec["approved_by"] == "operator"
    assert PendingStore(pending_path(eng)).list() == []


def test_approve_unknown_id_returns_refused(tmp_path):
    eng = make_eng(tmp_path)
    out = approve_action(eng, "deadbeef", approver="operator", runner=FakeRunner(), now=IN_WINDOW)
    assert out.status == "refused"


def test_phase_gated_approval_opens_phase(tmp_path):
    eng = make_eng(tmp_path, autonomy="phase-gated")
    runner = FakeRunner({"sqlmap a": ExecResult("a", 0, 0.1, False),
                         "sqlmap b": ExecResult("b", 0, 0.1, False)})
    p1 = submit_action(eng, target="www.acme.test", tool="sqlmap", command="sqlmap a",
                       declared_class="exploit", runner=runner, now=IN_WINDOW)
    assert p1.status == "pending"
    approve_action(eng, p1.pending_id, approver="operator", runner=runner, now=IN_WINDOW)
    p2 = submit_action(eng, target="www.acme.test", tool="sqlmap", command="sqlmap b",
                       declared_class="exploit", runner=runner, now=IN_WINDOW)
    assert p2.status == "executed"
