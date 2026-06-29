import json
from datetime import datetime
from grin.spine import submit_action, approve_action, deny_action, Outcome
from grin.engagement import validate_engagement, pending_path
from grin.pending import PendingStore
from grin.runner import FakeRunner, ExecResult

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


def test_approve_out_of_window_keeps_action_pending(tmp_path):
    eng = make_eng(tmp_path)
    runner = FakeRunner()
    pend = submit_action(eng, target="www.acme.test", tool="sqlmap", command="sqlmap x",
                         declared_class="exploit", runner=runner, now=IN_WINDOW)
    out_window = datetime(2026, 6, 20, 12, 0)
    out = approve_action(eng, pend.pending_id, approver="operator", runner=runner, now=out_window)
    assert out.status == "refused"
    assert "window" in out.reason.lower()
    # I1: not silently lost — still queued for a later in-window approval
    assert PendingStore(pending_path(eng)).list()[0]["id"] == pend.pending_id
    rec = _audit_lines(eng)[0]
    assert rec["decision"] == "refuse"
    assert rec["approved_by"] == "operator"


def test_approve_unknown_id_is_audited(tmp_path):
    eng = make_eng(tmp_path)
    out = approve_action(eng, "deadbeef", approver="operator", runner=FakeRunner(), now=IN_WINDOW)
    assert out.status == "refused"
    rec = _audit_lines(eng)[0]
    assert rec["decision"] == "refuse"
    assert "unknown pending id" in rec["reason"]
    assert rec["approved_by"] == "operator"


def test_deny_unknown_id_is_audited(tmp_path):
    eng = make_eng(tmp_path)
    out = deny_action(eng, "deadbeef", approver="operator")
    assert out.status == "refused"
    rec = _audit_lines(eng)[0]
    assert rec["decision"] == "refuse"
    assert "unknown pending id" in rec["reason"]


def test_execute_applies_stealth_and_audits_level(tmp_path):
    import json
    from grin.spine import _execute_and_audit
    from grin.engagement import Engagement, Scope, ROE

    class CapRunner:
        def __init__(self): self.cmd = None
        def run(self, target, command, timeout=60):
            self.cmd = command
            class R: exit_code = 0; output = ""; duration_s = 0.0
            return R()

    eng = Engagement(id="e", name="e", mode="adhoc", scope=Scope(["10.0.0.1"]), roe=ROE([]),
                     autonomy="autonomous", env={"kind": "local"},
                     audit_log=str(tmp_path / "a.jsonl"), state="active", stealth="quiet")
    r = CapRunner()
    _execute_and_audit(eng, target="10.0.0.1", tool="nmap", command="nmap -sV 10.0.0.1",
                       action_class="active-scan", gated=False, approved_by=None, runner=r)
    assert "-T2" in r.cmd
    rec = json.loads(open(eng.audit_log).read().splitlines()[0])
    assert rec["command"] == r.cmd
    assert rec["stealth"] == "quiet"


def test_execute_off_is_unchanged(tmp_path):
    from grin.spine import _execute_and_audit
    from grin.engagement import Engagement, Scope, ROE

    class CapRunner:
        def __init__(self): self.cmd = None
        def run(self, target, command, timeout=60):
            self.cmd = command
            class R: exit_code = 0; output = ""; duration_s = 0.0
            return R()

    eng = Engagement(id="e", name="e", mode="adhoc", scope=Scope(["t"]), roe=ROE([]),
                     autonomy="autonomous", env={"kind": "local"},
                     audit_log=str(tmp_path / "a.jsonl"), state="active")
    r = CapRunner()
    _execute_and_audit(eng, target="t", tool="nmap", command="nmap -sV t",
                       action_class="active-scan", gated=False, approved_by=None, runner=r)
    assert r.cmd == "nmap -sV t"


def test_apply_device_stealth_runs_and_audits(tmp_path, monkeypatch):
    import json
    from grin.spine import apply_device_stealth
    from grin.engagement import Engagement, Scope, ROE

    class CapRunner:
        def __init__(self): self.cmds = []
        def run(self, target, command, timeout=60):
            self.cmds.append(command)
            class R: exit_code = 0; output = ""; duration_s = 0.0
            return R()

    monkeypatch.setattr("grin.platform_info.host_has_arsenal", lambda *a, **k: True)
    monkeypatch.setattr("shutil.which", lambda t: "/usr/bin/macchanger" if t == "macchanger" else None)

    eng = Engagement(id="e", name="e", mode="adhoc", scope=Scope(["t"]), roe=ROE([]),
                     autonomy="autonomous", env={"kind": "local"},
                     audit_log=str(tmp_path / "a.jsonl"), state="active", stealth="paranoid")
    r = CapRunner()
    apply_device_stealth(eng, runner=r, iface="eth0")
    assert any("macchanger" in c for c in r.cmds)
    rec = json.loads(open(eng.audit_log).read().splitlines()[0])
    assert rec["stealth"] == "paranoid"


def test_apply_device_stealth_noop_when_incapable(tmp_path, monkeypatch):
    from grin.spine import apply_device_stealth
    from grin.engagement import Engagement, Scope, ROE
    monkeypatch.setattr("grin.platform_info.host_has_arsenal", lambda *a, **k: False)

    class CapRunner:
        def __init__(self): self.cmds = []
        def run(self, target, command, timeout=60):
            self.cmds.append(command)
            class R: exit_code = 0; output = ""; duration_s = 0.0
            return R()

    eng = Engagement(id="e", name="e", mode="adhoc", scope=Scope(["t"]), roe=ROE([]),
                     autonomy="autonomous", env={"kind": "local"},
                     audit_log=str(tmp_path / "a.jsonl"), state="active", stealth="paranoid")
    r = CapRunner()
    assert apply_device_stealth(eng, runner=r, iface="eth0") == []
    assert r.cmds == []


def test_apply_device_stealth_blocks_self_destructive_command(tmp_path, monkeypatch):
    # defense in depth: even this second execution path honors the R3 self-destructive guard
    import json
    from grin.spine import apply_device_stealth
    from grin.engagement import Engagement, Scope, ROE
    monkeypatch.setattr("grin.platform_info.host_has_arsenal", lambda *a, **k: True)
    monkeypatch.setattr("grin.stealth.device_setup", lambda *a, **k: ["rm -rf /"])

    class CapRunner:
        def __init__(self): self.cmds = []
        def run(self, target, command, timeout=60):
            self.cmds.append(command)
            class R: exit_code = 0; output = ""; duration_s = 0.0
            return R()

    eng = Engagement(id="e", name="e", mode="adhoc", scope=Scope(["t"]), roe=ROE([]),
                     autonomy="autonomous", env={"kind": "local"},
                     audit_log=str(tmp_path / "a.jsonl"), state="active", stealth="paranoid")
    r = CapRunner()
    recs = apply_device_stealth(eng, runner=r, iface="eth0")
    assert r.cmds == []                                   # never ran the destructive command
    assert recs and recs[0]["decision"] == "block" and recs[0]["reason"] == "self-destructive-blocked"
    rec = json.loads(open(eng.audit_log).read().splitlines()[0])
    assert rec["decision"] == "block"
