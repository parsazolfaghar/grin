import json
from datetime import datetime
from grin.orchestrator import orchestrate, EngagementResult
from grin.objective import Objective
from grin.engagement import validate_engagement
from grin.inference import FakeClient
from grin.runner import FakeRunner, ExecResult
from grin.finding import Finding

NOW = datetime(2026, 1, 1)


def make_eng(tmp_path, **over):
    d = {
        "id": "e1", "name": "n", "mode": "client",
        "scope": {"in": ["203.0.113.0/24"], "exclude": []},
        "roe": {"allowed_actions": ["passive", "active-scan", "exploit"], "windows": []},
        "autonomy": "autonomous", "env": {"kind": "local"},
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


def test_adaptive_loop_runs_followup_then_completes(tmp_path):
    eng = make_eng(tmp_path)
    planner = FakeClient([
        _plan([("enumerate hosts", "203.0.113.0/24")]),
        _replan(False, [("scan web", "203.0.113.7")], "found a web host"),
        _replan(True, [], "goal met"),
    ])
    executor = FakeClient([
        _ex_action("nmap", "nmap -sn 203.0.113.0/24", "203.0.113.0/24", "active-scan"),
        _ex_done([{"title": "host .7 up", "severity": "info", "evidence": ".7",
                   "tool": "nmap", "command": "nmap -sn 203.0.113.0/24"}]),
        _ex_action("whatweb", "whatweb 203.0.113.7", "203.0.113.7", "active-scan"),
        _ex_done([{"title": "nginx on .7", "severity": "low", "evidence": "Server: nginx",
                   "tool": "whatweb", "command": "whatweb 203.0.113.7"}]),
    ])
    runner = FakeRunner({
        "nmap -sn 203.0.113.0/24": ExecResult(".7 up", 0, 0.1, False),
        "whatweb 203.0.113.7": ExecResult("nginx", 0, 0.1, False),
    })
    res = orchestrate(eng, goal="assess network", planner_client=planner,
                      executor_client=executor, runner=runner, now=NOW, max_objectives=10)
    assert isinstance(res, EngagementResult)
    assert res.status == "completed"
    assert len(res.objectives_run) == 2
    titles = {f.title for f in res.findings}
    assert titles == {"host .7 up", "nginx on .7"}
    assert res.paused == []


def test_findings_are_deduped(tmp_path):
    eng = make_eng(tmp_path)
    planner = FakeClient([
        _plan([("o1", "203.0.113.7"), ("o2", "203.0.113.7")]),
        _replan(True, [], "done"),
    ])
    same = {"title": "dup", "severity": "info", "evidence": "e", "tool": "nmap", "command": "c"}
    # Each objective runs an action first so the evidence gate is satisfied before done.
    executor = FakeClient([
        _ex_action("nmap", "nmap -sV 203.0.113.7", "203.0.113.7", "active-scan"),
        _ex_done([same]),
        _ex_action("nmap", "nmap -sV 203.0.113.7", "203.0.113.7", "active-scan"),
        _ex_done([same]),
    ])
    runner = FakeRunner({"nmap -sV 203.0.113.7": ExecResult("ok", 0, 0.1, False)})
    res = orchestrate(eng, goal="g", planner_client=planner, executor_client=executor,
                      runner=runner, now=NOW, max_objectives=10)
    assert res.findings == [Finding(title="dup", target="203.0.113.7", severity="info",
                                    evidence="e", tool="nmap", command="c")]


def _ex_find(title, cmd, target):
    """Two executor replies: run a command, then report a finding (satisfies the evidence gate)."""
    return [_ex_action("nmap", cmd, target, "active-scan"),
            _ex_done([{"title": title, "severity": "info", "evidence": "e", "tool": "nmap",
                       "command": cmd}])]


def test_budget_caps_objectives_when_making_progress(tmp_path):
    # Each objective finds something NEW (so the no-progress stop doesn't fire), the analyst never
    # declares done, and the budget caps the loop at 3 -> budget_exhausted with the queue non-empty.
    eng = make_eng(tmp_path)
    planner = FakeClient(
        [_plan([("o1", "203.0.113.7")])]
        + [_replan(False, [("o%d" % i, "203.0.113.7")], "keep going") for i in range(2, 8)])
    executor = FakeClient(
        _ex_find("f1", "nmap a 203.0.113.7", "203.0.113.7")
        + _ex_find("f2", "nmap b 203.0.113.7", "203.0.113.7")
        + _ex_find("f3", "nmap c 203.0.113.7", "203.0.113.7"))
    runner = FakeRunner({"nmap a 203.0.113.7": ExecResult("a", 0, 0.1, False),
                         "nmap b 203.0.113.7": ExecResult("b", 0, 0.1, False),
                         "nmap c 203.0.113.7": ExecResult("c", 0, 0.1, False)})
    res = orchestrate(eng, goal="g", planner_client=planner, executor_client=executor,
                      runner=runner, now=NOW, max_objectives=3)
    assert res.status == "budget_exhausted"
    assert len(res.objectives_run) == 3


def test_no_progress_concludes_before_budget(tmp_path):
    # Every objective completes with no new finding/secret -> the loop concludes (stall) well before
    # the objective budget, instead of flailing to it.
    eng = make_eng(tmp_path)
    planner = FakeClient(
        [_plan([("o1", "203.0.113.7")])]
        + [_replan(False, [("o%d" % i, "203.0.113.7")], "keep going") for i in range(2, 12)])
    executor = FakeClient(_ex_done([]))   # always done, nothing found
    res = orchestrate(eng, goal="g", planner_client=planner, executor_client=executor,
                      runner=FakeRunner(), now=NOW, max_objectives=10)
    assert res.status == "completed"
    assert len(res.objectives_run) <= 3   # stalled out early, did not reach the budget of 10


def test_recon_discovering_new_hosts_resets_stall(tmp_path):
    # A pure-recon engagement (ping sweeps, no findings/secrets) must NOT be mistaken for stalling
    # while it keeps discovering NEW live hosts. o1/o2 find new hosts (progress -> stall resets);
    # o3/o4 only re-find seen hosts (no progress -> stall hits 2 -> conclude). So it runs 4
    # objectives, not 2. Each objective uses a distinct command to avoid cross-objective dedup.
    eng = make_eng(tmp_path)
    tgt = "203.0.113.0/24"  # in scope; vary only the command to dodge cross-objective dedup
    cmds = [f"nmap -sn {flag} {tgt}" for flag in ("-PE", "-PP", "-PM", "-PS22")]
    planner = FakeClient(
        [_plan([("o1", tgt)])]
        + [_replan(False, [("o%d" % i, tgt)], "keep sweeping") for i in range(2, 5)])
    ex = []
    for c in cmds:
        ex += [_ex_action("nmap", c, tgt, "active-scan"), _ex_done([])]
    executor = FakeClient(ex)

    def _up(*ips):
        return "".join(f"Nmap scan report for {ip}\nHost is up (0.005s latency).\n" for ip in ips)
    runner = FakeRunner({
        cmds[0]: ExecResult(_up("203.0.113.1", "203.0.113.2"), 0, 0.1, False),
        cmds[1]: ExecResult(_up("203.0.113.130"), 0, 0.1, False),  # new host -> progress
        cmds[2]: ExecResult(_up("203.0.113.1"), 0, 0.1, False),    # already seen -> stall 1
        cmds[3]: ExecResult(_up("203.0.113.2"), 0, 0.1, False),    # already seen -> stall 2
    })
    res = orchestrate(eng, goal="map the network", planner_client=planner,
                      executor_client=executor, runner=runner, now=NOW, max_objectives=10)
    assert res.status == "completed"
    assert len(res.objectives_run) == 4   # would be 2 if recon didn't count as progress


def test_captured_flag_concludes_immediately(tmp_path):
    # A flag is auto-extracted from tool output in the first objective. Even though the analyst says
    # "not done", the loop concludes at once (a flag is terminal proof) rather than running on.
    eng = make_eng(tmp_path)
    planner = FakeClient([
        _plan([("probe", "203.0.113.7")]),
        _replan(False, [("more", "203.0.113.7")], "keep going"),  # analyst would continue...
    ])
    executor = FakeClient([
        _ex_action("curl", "curl http://203.0.113.7/diag", "203.0.113.7", "active-scan"),
        _ex_done([]),
    ])
    runner = FakeRunner({"curl http://203.0.113.7/diag":
                         ExecResult("secret_flag: GRIN{deadbeef}", 0, 0.1, False)})
    res = orchestrate(eng, goal="capture the flag", planner_client=planner,
                      executor_client=executor, runner=runner, now=NOW, max_objectives=10)
    assert res.status == "completed"
    assert len(res.objectives_run) == 1   # stopped right after the flag, did not run "more"
    assert any(getattr(s, "label", "") == "flag" for s in res.secrets)


def test_gated_objective_pauses_and_loop_continues(tmp_path):
    eng = make_eng(tmp_path, autonomy="action-gated")
    planner = FakeClient([
        _plan([("exploit it", "203.0.113.7"), ("recon", "203.0.113.7")]),
        _replan(True, [], "done"),
    ])
    executor = FakeClient([
        _ex_action("sqlmap", "sqlmap -u http://203.0.113.7", "203.0.113.7", "exploit"),
        _ex_action("whatweb", "whatweb 203.0.113.7", "203.0.113.7", "active-scan"),
        _ex_done([{"title": "nginx", "severity": "info", "evidence": "x", "tool": "whatweb",
                   "command": "whatweb 203.0.113.7"}]),
    ])
    runner = FakeRunner({"whatweb 203.0.113.7": ExecResult("nginx", 0, 0.1, False)})
    res = orchestrate(eng, goal="g", planner_client=planner, executor_client=executor,
                      runner=runner, now=NOW, max_objectives=10)
    assert len(res.paused) == 1
    assert res.paused[0]["objective"] == Objective("exploit it", "203.0.113.7")
    assert res.paused[0]["pending_id"]
    assert len(res.objectives_run) == 2
    assert any(f.title == "nginx" for f in res.findings)


def test_model_down_aborts(tmp_path):
    eng = make_eng(tmp_path)
    res = orchestrate(eng, goal="g", planner_client=FakeClient("x", up=False),
                      executor_client=FakeClient("x"), runner=FakeRunner(), now=NOW)
    assert res.status == "model_unavailable"
    assert res.objectives_run == []


def test_empty_initial_plan_completes_with_no_findings(tmp_path):
    eng = make_eng(tmp_path)
    res = orchestrate(eng, goal="g", planner_client=FakeClient("not json"),
                      executor_client=FakeClient("x"), runner=FakeRunner(), now=NOW)
    assert res.status == "completed"
    assert res.findings == []
    assert res.objectives_run == []


def test_flag_honeypot_advisory_once_and_silent_when_clean():
    from grin.orchestrator import _flag_honeypot
    suspicious = [Finding("x", "t", "info", "banner: Cowrie SSH honeypot", "nmap", "c", "")]
    _flag_honeypot(suspicious); _flag_honeypot(suspicious)   # idempotent
    assert sum(1 for f in suspicious if "Suspected honeypot" in f.title) == 1
    clean = [Finding("ssh", "t", "info", "22/tcp open ssh OpenSSH 10.3", "nmap", "c", "")]
    _flag_honeypot(clean)
    assert all("Suspected" not in f.title for f in clean)


def test_honeypot_advisory_emitted_in_loop_but_does_not_block(tmp_path):
    eng = make_eng(tmp_path)
    planner = FakeClient([_plan([("scan web", "203.0.113.7")]), _replan(True)])
    executor = FakeClient([
        _ex_action("nmap", "nmap -sV 203.0.113.7", "203.0.113.7", "active-scan"),
        _ex_done([{"title": "SSH", "target": "203.0.113.7", "severity": "info",
                   "evidence": "22/tcp open ssh banner: Cowrie SSH honeypot", "tool": "nmap",
                   "command": "nmap", "recommendation": ""}]),
    ])
    runner = FakeRunner({"nmap -sV 203.0.113.7": ExecResult("cowrie honeypot", 0, 0.1, False)})
    res = orchestrate(eng, goal="g", planner_client=planner, executor_client=executor,
                      runner=runner, now=NOW, model="m", max_objectives=3,
                      engagement_path=str(tmp_path / "e1.yaml"))
    titles = [f.title for f in res.findings]
    assert "Suspected honeypot/decoy (advisory)" in titles   # advisory emitted
    assert any("SSH" in t for t in titles)                   # original finding kept (not removed)
    assert res.status == "completed"                         # never blocked the engagement


def test_drive_loop_checkpoint_stop(monkeypatch):
    import grin.orchestrator as orch
    from grin.orchestrator import _drive_loop
    from grin.secret import Secret
    from collections import namedtuple
    Obj = namedtuple("Obj", "objective target")

    class Res:
        status = "completed"; findings = []; pending_id = None
        secrets = [Secret(label="flag", value="GRIN{a}", target="t1", tool="x",
                          command="c", context="ctx")]
        class journal: path = "j"

    monkeypatch.setattr(orch, "execute_task", lambda *a, **k: Res())
    monkeypatch.setattr(orch, "replan", lambda *a, **k: type("D", (), {"done": False, "reason": "",
                                                                       "next_objectives": []})())

    class Loot:
        def record(self, *a, **k): pass

    calls = []
    def cp(flag, target):
        calls.append((flag, target)); return "stop"

    q = [Obj("o1", "t1"), Obj("o2", "t1")]
    status = _drive_loop(
        type("E", (), {"scope": type("S", (), {"include": ["t1"]})()})(),
        goal="g", queue=q, findings=[], objectives_run=[], paused=[], plan_log=[],
        planner_client=None, executor_client=None, runner=None, now=None, planner_model="m",
        objective_models=None, base_model="m", max_objectives=10, max_steps=5,
        engagement_path="", secrets=[], loot=Loot(), scope_targets=["t1"],
        aggressive=True, catalog=None, checkpoint_fn=cp)
    assert calls == [("GRIN{a}", "t1")]
    assert status == "completed"
    assert q == []


def test_drive_loop_no_checkpoint_when_not_aggressive(monkeypatch):
    import grin.orchestrator as orch
    from grin.orchestrator import _drive_loop
    from grin.secret import Secret
    from collections import namedtuple
    Obj = namedtuple("Obj", "objective target")

    class Res:
        status = "completed"; findings = []; pending_id = None
        secrets = [Secret(label="flag", value="GRIN{a}", target="t1", tool="x",
                          command="c", context="ctx")]
        class journal: path = "j"

    monkeypatch.setattr(orch, "execute_task", lambda *a, **k: Res())
    monkeypatch.setattr(orch, "replan", lambda *a, **k: type("D", (), {"done": True, "reason": "",
                                                                       "next_objectives": []})())

    class Loot:
        def record(self, *a, **k): pass

    fired = []
    _drive_loop(
        type("E", (), {"scope": type("S", (), {"include": ["t1"]})()})(),
        goal="g", queue=[Obj("o1", "t1")], findings=[], objectives_run=[], paused=[], plan_log=[],
        planner_client=None, executor_client=None, runner=None, now=None, planner_model="m",
        objective_models=None, base_model="m", max_objectives=10, max_steps=5,
        engagement_path="", secrets=[], loot=Loot(), scope_targets=["t1"],
        aggressive=False, catalog=None, checkpoint_fn=lambda *a: fired.append(a) or "stop")
    assert fired == []


def test_drive_loop_should_stop_ends_run(monkeypatch):
    import grin.orchestrator as orch
    from grin.orchestrator import _drive_loop
    from collections import namedtuple
    Obj = namedtuple("Obj", "objective target")
    ran = []

    class Res:
        status = "completed"; findings = []; pending_id = None; secrets = []
        class journal: path = "j"

    def fake_exec(*a, **k):
        ran.append(1); return Res()
    monkeypatch.setattr(orch, "execute_task", fake_exec)
    monkeypatch.setattr(orch, "replan", lambda *a, **k: type("D", (), {"done": False, "reason": "",
                                                                       "next_objectives": []})())

    class Loot:
        def record(self, *a, **k): pass

    status = _drive_loop(
        type("E", (), {"scope": type("S", (), {"include": ["t1"]})()})(),
        goal="g", queue=[Obj("o1", "t1"), Obj("o2", "t1")], findings=[], objectives_run=[],
        paused=[], plan_log=[], planner_client=None, executor_client=None, runner=None, now=None,
        planner_model="m", objective_models=None, base_model="m", max_objectives=10, max_steps=5,
        engagement_path="", secrets=[], loot=Loot(), scope_targets=["t1"],
        should_stop=lambda: True)            # already cancelled -> stop before running anything
    assert status == "stopped"
    assert ran == []
