import threading
from grin.app.runner_thread import JobRunner


def test_checkpoint_blocks_until_resolved():
    eng = type("E", (), {"env": {}})()
    jr = JobRunner(eng, goal="g", orchestrate_fn=lambda *a, **k: None,
                   save_fn=lambda *a, **k: None, snapshot_reader=lambda e: {})
    result = {}

    def worker():
        result["decision"] = jr.checkpoint_fn("GRIN{a}", "t1")

    t = threading.Thread(target=worker); t.start()
    for _ in range(100):
        if jr.snapshot().get("checkpoint"):
            break
    cp = jr.snapshot().get("checkpoint")
    assert cp == {"flag": "GRIN{a}", "target": "t1"}
    jr.resolve("focus")
    t.join(timeout=2)
    assert result["decision"] == "focus"
    assert jr.snapshot().get("checkpoint") is None


def test_resolve_ignored_when_no_checkpoint_pending():
    eng = type("E", (), {"env": {}})()
    jr = JobRunner(eng, goal="g", orchestrate_fn=lambda *a, **k: None,
                   save_fn=lambda *a, **k: None, snapshot_reader=lambda e: {})
    jr.resolve("focus")                 # no checkpoint pending -> must not arm the event
    assert jr._cp_event.is_set() is False
