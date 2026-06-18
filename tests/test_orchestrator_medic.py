from datetime import datetime

import grin.orchestrator as orch
from grin.orchestrator import _drive_loop
from grin.engagement import validate_engagement
from grin.inference import FakeClient
from grin.journal import Journal, Step
from grin.executor import TaskResult
from grin.objective import Objective
from grin.medic import MedicDecision

NOW = datetime(2026, 1, 1)


class _FakeLoot:
    def record(self, *a, **k):
        pass


def _eng(tmp_path):
    return validate_engagement({
        "id": "e", "name": "n", "mode": "own-lab",
        "scope": {"in": ["172.30.0.12"], "exclude": []},
        "roe": {"allowed_actions": ["active-scan", "exploit"], "windows": []},
        "autonomy": "autonomous", "env": {"kind": "local"},
        "audit_log": str(tmp_path / "audit" / "e.jsonl"), "state": "active"})


def _no_progress_executor(tmp_path):
    # Every objective "runs" an executed command but yields NO output/findings/secrets -> the
    # orchestrator sees no progress and the stall counter climbs.
    def fake_execute(eng, *, objective, target, client, runner, now, model, max_steps,
                     engagement_path, executed_commands):
        j = Journal(task_id="x", objective=objective, target=target, engagement_path="",
                    path=str(tmp_path / "j.json"), max_steps=max_steps)
        j.add_step(Step(action={"command": "curl ...", "target": target, "tool": "curl",
                                "declared_class": "exploit"},
                        decision="executed", output="", exit_code=0, extracted=[]))
        return TaskResult("completed", [], j, secrets=[])
    return fake_execute


def _run(tmp_path, queue, stub_medic):
    eng = _eng(tmp_path)
    findings, objectives_run, secrets = [], [], []
    status = _drive_loop(
        eng, goal="capture flag", queue=list(queue), findings=findings,
        objectives_run=objectives_run, paused=[], plan_log=[],
        planner_client=FakeClient('{"done": false, "next_objectives": []}'),
        executor_client=FakeClient("{}"), runner=None, now=NOW, planner_model="m",
        objective_models=None, base_model="m", max_objectives=20, max_steps=4,
        engagement_path="", secrets=secrets, loot=_FakeLoot(), scope_targets=["172.30.0.12"],
        medic_triage=stub_medic)
    return status, findings, objectives_run


def test_stall_pages_medic_and_runs_recover_objective(tmp_path, monkeypatch):
    monkeypatch.setattr(orch, "execute_task", _no_progress_executor(tmp_path))
    calls = {"n": 0}

    def stub_medic(client, model, **kw):
        calls["n"] += 1
        return MedicDecision(action="recover",
                             objectives=[Objective("read /flag.txt", "172.30.0.12", "exploit")])

    queue = [Objective("o1", "172.30.0.12", "exploit"),
             Objective("o2", "172.30.0.12", "exploit")]
    status, findings, objectives_run = _run(tmp_path, queue, stub_medic)

    assert calls["n"] >= 1                                                # Medic paged on stall
    assert any(o.objective == "read /flag.txt" for o in objectives_run)   # recover objective ran


def test_empty_initial_plan_seeds_fallback_objective(tmp_path, monkeypatch):
    # Regression for the validated T5 anomaly: when initial_plan returns nothing, the engagement
    # must NOT silently complete with 0 objectives — it seeds a recon objective per scope target.
    from grin.orchestrator import orchestrate
    monkeypatch.setattr(orch, "initial_plan", lambda *a, **k: [])
    ran = {"objectives": []}

    def fake_execute(eng, *, objective, target, client, runner, now, model, max_steps,
                     engagement_path, executed_commands):
        ran["objectives"].append(objective)
        j = Journal(task_id="x", objective=objective, target=target, engagement_path="",
                    path=str(tmp_path / "j.json"), max_steps=max_steps)
        j.add_step(Step(action={"command": "nmap", "target": target, "tool": "nmap",
                                "declared_class": "active-scan"},
                        decision="executed", output="", exit_code=0, extracted=[]))
        return TaskResult("completed", [], j, secrets=[])
    monkeypatch.setattr(orch, "execute_task", fake_execute)

    orchestrate(_eng(tmp_path), goal="capture flag",
                planner_client=FakeClient('{"done": true, "next_objectives": []}'),
                executor_client=FakeClient("{}"), runner=None, now=NOW,
                model="m", planner_model="m", max_objectives=5)
    assert len(ran["objectives"]) >= 1   # fallback recon objective actually ran
    assert "172.30.0.12" in ran["objectives"][0] or "enumerate" in ran["objectives"][0]


def test_medic_patch_proposal_written_to_review_file(tmp_path, monkeypatch):
    # With medic_patches=True, a CONCLUDE carrying a patch must be written to a review file next to
    # the audit log (human-review only — never applied).
    import glob
    import os
    monkeypatch.setattr(orch, "execute_task", _no_progress_executor(tmp_path))

    def stub_medic(client, model, **kw):
        assert kw.get("propose_patches") is True   # flag threaded through
        return MedicDecision(action="conclude", diagnosis="no extractor for the loot type",
                             patch="add a regex to grin/extractors.py")

    eng = _eng(tmp_path)
    queue = [Objective("o1", "172.30.0.12", "exploit"), Objective("o2", "172.30.0.12", "exploit")]
    _drive_loop(eng, goal="g", queue=queue, findings=[], objectives_run=[], paused=[], plan_log=[],
                planner_client=FakeClient('{"done": false, "next_objectives": []}'),
                executor_client=FakeClient("{}"), runner=None, now=NOW, planner_model="m",
                objective_models=None, base_model="m", max_objectives=20, max_steps=4,
                engagement_path="", secrets=[], loot=_FakeLoot(), scope_targets=["172.30.0.12"],
                medic_triage=stub_medic, medic_patches=True)

    patches = glob.glob(os.path.join(os.path.dirname(eng.audit_log), "*.medic-patch.md"))
    assert patches, "patch proposal file not written"
    body = open(patches[0]).read()
    assert "extractors.py" in body and "REVIEW ONLY" in body


def _activity_no_capture_executor(tmp_path):
    # Each objective produces DISTINCT non-empty output (so output_keys grows -> the dead-stall
    # never trips) but never a finding/secret -> "productive wandering" (the T2 failure mode).
    n = {"i": 0}

    def fake_execute(eng, *, objective, target, client, runner, now, model, max_steps,
                     engagement_path, executed_commands):
        n["i"] += 1
        j = Journal(task_id="x", objective=objective, target=target, engagement_path="",
                    path=str(tmp_path / "j.json"), max_steps=max_steps)
        j.add_step(Step(action={"command": f"curl c{n['i']}", "target": target, "tool": "curl",
                                "declared_class": "exploit"},
                        decision="executed", output=f"uid=33(www-data) distinct-{n['i']}",
                        exit_code=0, extracted=[]))
        return TaskResult("completed", [], j, secrets=[])
    return fake_execute


def test_medic_pages_on_no_capture_even_with_output_activity(tmp_path, monkeypatch):
    # Regression for the validated T2 gap: lots of command output but no captured finding/secret
    # must still page the Medic (it should not need a dead stall to fire).
    monkeypatch.setattr(orch, "execute_task", _activity_no_capture_executor(tmp_path))
    calls = {"n": 0}

    def stub_medic(client, model, **kw):
        calls["n"] += 1
        return MedicDecision(action="recover",
                             objectives=[Objective(f"read /flag.txt try {calls['n']}",
                                                   "172.30.0.12", "exploit")])

    queue = [Objective(f"o{i}", "172.30.0.12", "exploit") for i in range(5)]
    status, findings, objectives_run = _run(tmp_path, queue, stub_medic)

    assert calls["n"] >= 1                                                   # Medic paged despite activity
    assert any("read /flag.txt" in o.objective for o in objectives_run)      # its redirect ran


def test_stall_medic_conclude_emits_diagnosis_finding(tmp_path, monkeypatch):
    monkeypatch.setattr(orch, "execute_task", _no_progress_executor(tmp_path))

    def stub_medic(client, model, **kw):
        return MedicDecision(action="conclude", diagnosis="RCE achieved but flag unreadable.")

    queue = [Objective("o1", "172.30.0.12", "exploit"),
             Objective("o2", "172.30.0.12", "exploit")]
    status, findings, objectives_run = _run(tmp_path, queue, stub_medic)

    assert status == "completed"
    medic_findings = [f for f in findings if f.tool == "medic"]
    assert len(medic_findings) == 1
    assert "flag" in medic_findings[0].evidence
