from grin.app.api import GrinApi


class FakeOllama:
    def is_up(self): return False
    def generate(self, **k): raise AssertionError("should not be called")


def _api(tmp_path):
    api = GrinApi(engagements_dir=str(tmp_path), ollama=FakeOllama())
    api._tool_env = {"kind": "local"}
    return api


def test_interpret_returns_intent_and_manual(tmp_path):
    api = _api(tmp_path)
    out = api.interpret("bypass login page for www.test.com")
    assert out["targets"] == ["www.test.com"]
    assert out["target_type"] == "web-url"
    assert out["bare_target"] is False
    assert out["manual"]["sections"]
    assert out["allowed_actions"]


def test_interpret_no_target(tmp_path):
    api = _api(tmp_path)
    out = api.interpret("just chatting")
    assert out["targets"] == []
    assert out["can_engage"] is False


def test_engage_text_builds_and_starts(tmp_path, monkeypatch):
    api = _api(tmp_path)
    calls = {}

    def fake_start(file, goal, **opts):
        calls["file"] = file
        calls["goal"] = goal
        calls["opts"] = opts
        return {"job_id": "j1", "started": True}

    monkeypatch.setattr(api, "start_engagement", fake_start)
    res = api.engage_text("www.test.com")
    assert res["started"] is True
    assert calls["opts"].get("aggressive") is True
    assert calls["file"].endswith(".yaml")


def test_engage_text_no_target_errors(tmp_path):
    api = _api(tmp_path)
    res = api.engage_text("nothing here")
    assert "error" in res


def test_set_stealth_flows_into_engagement(tmp_path, monkeypatch):
    api = _api(tmp_path)
    api.set_stealth("quiet")
    captured = {}

    def fake_start(file, goal, **opts):
        from grin.engagement import load_engagement
        captured["stealth"] = load_engagement(file).stealth
        return {"started": True}

    monkeypatch.setattr(api, "start_engagement", fake_start)
    api.engage_text("www.test.com")
    assert captured["stealth"] == "quiet"
