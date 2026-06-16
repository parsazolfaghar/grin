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
    assert calls["opts"].get("aggressive") is False
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


def test_set_strength_drives_orchestrate_opts(tmp_path, monkeypatch):
    api = _api(tmp_path)
    api.set_strength("max")
    captured = {}

    def fake_start(file, goal, **opts):
        from grin.engagement import load_engagement
        captured["opts"] = opts
        captured["strength"] = load_engagement(file).strength
        return {"started": True}

    monkeypatch.setattr(api, "start_engagement", fake_start)
    api.engage_text("www.test.com")
    assert captured["strength"] == "max"
    assert captured["opts"]["aggressive"] is True
    assert captured["opts"]["max_objectives"] == 40
    assert captured["opts"]["max_steps"] == 20
    assert "catalog" in captured["opts"]


def test_recon_strength_not_aggressive(tmp_path, monkeypatch):
    api = _api(tmp_path)
    api.set_strength("recon")
    captured = {}

    def fake_start(file, goal, **opts):
        captured["opts"] = opts
        return {"started": True}

    monkeypatch.setattr(api, "start_engagement", fake_start)
    api.engage_text("www.test.com")
    assert captured["opts"]["aggressive"] is False
    assert captured["opts"]["max_objectives"] == 5
    assert "catalog" not in captured["opts"]


def test_pending_and_approve_tool(tmp_path, monkeypatch):
    from datetime import datetime
    from grin.adhoc import build_adhoc_engagement
    from grin.intent import parse_intent
    from grin.toolrequest import ToolRequestStore, tool_requests_path
    from grin.engagement import load_engagement
    api = _api(tmp_path)
    _e, path = build_adhoc_engagement(parse_intent("www.test.com"),
                                      now=datetime(2026, 6, 15, 12, 0, 0), operator="op",
                                      root=str(tmp_path), tool_acquire="ask")
    eng = load_engagement(path)
    ToolRequestStore(tool_requests_path(eng)).request("sqlmap")
    assert api.pending_tools(path) == ["sqlmap"]
    installs = []
    monkeypatch.setattr("grin.arsenal.run_add", lambda t: installs.append(t) or 0)
    out = api.approve_tool(path, "sqlmap")
    assert out.get("status") == "installed"
    assert installs == ["sqlmap"]
    assert api.pending_tools(path) == []


def test_deny_tool(tmp_path):
    from datetime import datetime
    from grin.adhoc import build_adhoc_engagement
    from grin.intent import parse_intent
    from grin.toolrequest import ToolRequestStore, tool_requests_path
    from grin.engagement import load_engagement
    api = _api(tmp_path)
    _e, path = build_adhoc_engagement(parse_intent("www.test.com"),
                                      now=datetime(2026, 6, 15, 12, 0, 0), operator="op",
                                      root=str(tmp_path), tool_acquire="ask")
    eng = load_engagement(path)
    ToolRequestStore(tool_requests_path(eng)).request("hydra")
    assert api.deny_tool(path, "hydra").get("status") == "denied"
    assert api.pending_tools(path) == []


def test_engage_text_passes_tool_acquire(tmp_path, monkeypatch):
    api = _api(tmp_path)
    api.set_tool_acquire("never")
    captured = {}

    def fake_start(file, goal, **opts):
        from grin.engagement import load_engagement
        captured["env"] = load_engagement(file).env
        return {"started": True}

    monkeypatch.setattr(api, "start_engagement", fake_start)
    api.engage_text("www.test.com")
    assert captured["env"]["tool_acquire"] == "never"


def test_approve_tool_rejects_unsafe_name(tmp_path):
    from datetime import datetime
    from grin.adhoc import build_adhoc_engagement
    from grin.intent import parse_intent
    api = _api(tmp_path)
    _e, path = build_adhoc_engagement(parse_intent("www.test.com"),
                                      now=datetime(2026, 6, 15, 12, 0, 0), operator="op",
                                      root=str(tmp_path), tool_acquire="ask")
    out = api.approve_tool(path, "sqlmap; rm -rf /")
    assert "error" in out and "unsafe" in out["error"].lower()


def test_engage_text_returns_file(tmp_path, monkeypatch):
    api = _api(tmp_path)
    monkeypatch.setattr(api, "start_engagement",
                        lambda file, goal, **opts: {"job_id": "j1", "started": True})
    res = api.engage_text("www.test.com")
    assert res["file"].endswith(".yaml")     # GUI can bind to this engagement


def test_resolve_checkpoint(tmp_path):
    api = _api(tmp_path)

    class FakeJob:
        def __init__(self): self.resolved = None
        def resolve(self, d): self.resolved = d
    job = FakeJob()
    api._jobs["j1"] = ("f.yaml", job)
    out = api.resolve_checkpoint("j1", "focus")
    assert out.get("status") == "resumed" and out.get("decision") == "focus"
    assert job.resolved == "focus"


def test_resolve_checkpoint_invalid(tmp_path):
    api = _api(tmp_path)

    class FakeJob:
        def resolve(self, d): raise AssertionError("must not be called")
    api._jobs["j1"] = ("f.yaml", FakeJob())
    assert "error" in api.resolve_checkpoint("j1", "bogus")
    assert "error" in api.resolve_checkpoint("nope", "focus")


def test_stop_engagement(tmp_path):
    api = _api(tmp_path)

    class FakeJob:
        def __init__(self): self.cancelled = False
        def cancel(self): self.cancelled = True
    job = FakeJob()
    api._jobs["j1"] = ("f.yaml", job)
    assert api.stop_engagement("j1").get("status") == "stopping"
    assert job.cancelled is True
    assert "error" in api.stop_engagement("nope")
