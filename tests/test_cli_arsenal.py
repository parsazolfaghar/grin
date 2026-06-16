from grin import cli


def test_arsenal_up_dispatches(monkeypatch):
    called = {}
    monkeypatch.setattr(cli, "arsenal_up", lambda: called.update({"up": True}) or 0)
    assert cli.main(["arsenal", "up"]) == 0 and called.get("up")


def test_arsenal_status_dispatches(monkeypatch):
    monkeypatch.setattr(cli, "arsenal_status", lambda: 0)
    assert cli.main(["arsenal", "status"]) == 0


def test_arsenal_add_dispatches(monkeypatch):
    got = {}
    monkeypatch.setattr(cli, "arsenal_add", lambda tool: got.update({"tool": tool}) or 0)
    assert cli.main(["arsenal", "add", "wfuzz"]) == 0
    assert got["tool"] == "wfuzz"
