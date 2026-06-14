import json
from pathlib import Path
from grin.app.api import GrinApi
from grin.spine import Outcome

EXAMPLE = """
id: t-act
name: act
mode: client
scope: {{include: ["127.0.0.1"], exclude: []}}
roe: {{allowed_actions: ["passive","active-scan","exploit"], windows: []}}
autonomy: action-gated
env: {{kind: local}}
audit_log: "{audit}"
state: active
"""

def _eng(tmp_path):
    audit = str(tmp_path / "a.jsonl")
    f = tmp_path / "t-act.yaml"
    f.write_text(EXAMPLE.format(audit=audit))
    return str(f)

def test_approve_calls_spine(tmp_path):
    seen = {}
    def fake_approve(eng, pid, *, approver, runner, now):
        seen["pid"] = pid
        return Outcome(status="executed", reason="ran")
    api = GrinApi(engagements_dir=str(tmp_path), approve_fn=fake_approve,
                  runner_factory=lambda env: None)
    out = api.approve(_eng(tmp_path), "p-1")
    assert seen["pid"] == "p-1"
    assert out["status"] == "executed"
    json.dumps(out)

def test_deny_calls_spine(tmp_path):
    def fake_deny(eng, pid, *, approver):
        return Outcome(status="denied")
    api = GrinApi(engagements_dir=str(tmp_path), deny_fn=fake_deny,
                  runner_factory=lambda env: None)
    out = api.deny(_eng(tmp_path), "p-9")
    assert out["status"] == "denied"

def test_start_and_state_with_fake_jobrunner(tmp_path):
    class FakeJob:
        def __init__(self, eng, **kw): self.started = False
        def start(self): self.started = True
        def snapshot(self): return {"status": "running", "findings": []}
    api = GrinApi(engagements_dir=str(tmp_path), job_runner_factory=lambda eng, **kw: FakeJob(eng))
    started = api.start_engagement(_eng(tmp_path), "assess it")
    assert started["started"] is True and "job_id" in started
    st = api.engagement_state(started["job_id"])
    assert st["status"] == "running"
    assert "error" in api.engagement_state("nope")

def test_approve_bad_id_returns_error(tmp_path):
    def fake_approve(eng, pid, *, approver, runner, now):
        raise KeyError("no such pending")
    api = GrinApi(engagements_dir=str(tmp_path), approve_fn=fake_approve,
                  runner_factory=lambda env: None)
    out = api.approve(_eng(tmp_path), "bad")
    assert "error" in out


def test_set_backend_threads_tool_env_into_jobrunner(tmp_path):
    captured = {}
    class FakeJob:
        def __init__(self, eng, **kw): captured.update(kw)
        def start(self): pass
        def snapshot(self): return {}
    api = GrinApi(engagements_dir=str(tmp_path),
                  job_runner_factory=lambda eng, **kw: FakeJob(eng, **kw))
    api.set_backend({"kind": "ssh", "ssh_host": "root@rig"})
    api.start_engagement(_eng(tmp_path), "goal")
    assert captured["env"] == {"kind": "ssh", "ssh_host": "root@rig"}
