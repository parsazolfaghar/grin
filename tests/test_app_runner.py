import time
from grin.app.runner_thread import JobRunner
from grin.orchestrator import EngagementResult

class _Eng:
    id = "e"; env = {"kind": "local"}; audit_log = "/tmp/none.jsonl"

def test_jobrunner_runs_and_completes():
    calls = {}
    def fake_orch(eng, **kw):
        calls["ran"] = True
        return EngagementResult(status="completed", findings=[])
    saved = {}
    jr = JobRunner(_Eng(), goal="g", orchestrate_fn=fake_orch,
                   save_fn=lambda eng, res: saved.setdefault("res", res),
                   snapshot_reader=lambda eng: {"status": "x"})
    jr.start()
    for _ in range(100):
        if jr.status in ("completed", "error"):
            break
        time.sleep(0.01)
    assert jr.status == "completed"
    assert calls.get("ran") and "res" in saved

def test_jobrunner_captures_error():
    def boom(eng, **kw):
        raise RuntimeError("kaboom")
    jr = JobRunner(_Eng(), goal="g", orchestrate_fn=boom,
                   save_fn=lambda *a: None, snapshot_reader=lambda eng: {})
    jr.start()
    for _ in range(100):
        if jr.status in ("completed", "error"):
            break
        time.sleep(0.01)
    assert jr.status == "error"
    assert "kaboom" in jr.error

def test_snapshot_merges_status():
    jr = JobRunner(_Eng(), goal="g", orchestrate_fn=lambda e, **k: None,
                   save_fn=lambda *a: None,
                   snapshot_reader=lambda eng: {"findings": [1], "audit": []})
    snap = jr.snapshot()
    assert snap["status"] == "idle"          # not started yet
    assert snap["findings"] == [1]
