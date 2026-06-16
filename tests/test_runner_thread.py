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


def test_cancel_sets_should_stop_and_unblocks_checkpoint():
    import threading
    eng = type("E", (), {"env": {}})()
    jr = JobRunner(eng, goal="g", orchestrate_fn=lambda *a, **k: None,
                   save_fn=lambda *a, **k: None, snapshot_reader=lambda e: {})
    assert jr.should_stop() is False
    # a thread parked at a checkpoint gets unblocked with "stop" on cancel
    out = {}
    t = threading.Thread(target=lambda: out.__setitem__("d", jr.checkpoint_fn("GRIN{a}", "t1")))
    t.start()
    for _ in range(100):
        if jr.snapshot().get("checkpoint"):
            break
    jr.cancel()
    t.join(timeout=2)
    assert jr.should_stop() is True
    assert out["d"] == "stop"
