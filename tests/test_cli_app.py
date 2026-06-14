import grin.cli as cli

def test_app_dispatch_calls_launch(monkeypatch):
    called = {}
    monkeypatch.setattr("grin.app.launch.main", lambda argv=None: called.setdefault("ran", True) and 0)
    rc = cli.main(["app"])
    assert called.get("ran") and rc == 0
