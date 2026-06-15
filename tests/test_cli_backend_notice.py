from grin import cli


def _eng_yaml(tmp_path):
    import yaml
    d = {"id": "e", "name": "n", "mode": "own-lab",
         "scope": {"in": ["172.30.0.11"], "exclude": []},
         "roe": {"allowed_actions": ["active-scan", "exploit", "post-exploit"], "windows": []},
         "autonomy": "autonomous", "env": {"kind": "local"},
         "audit_log": str(tmp_path / "audit" / "e.jsonl"), "state": "active"}
    p = tmp_path / "e.yaml"
    p.write_text(yaml.safe_dump(d))
    return str(p)


def _patch_run(monkeypatch):
    def fake_orchestrate(eng, **kw):
        from grin.orchestrator import EngagementResult
        return EngagementResult("completed", [], [], [], [], goal=kw.get("goal", ""))
    monkeypatch.setattr(cli, "orchestrate", fake_orchestrate)
    monkeypatch.setattr(cli, "save_result", lambda *a, **k: None)


def test_notice_shows_local(tmp_path, monkeypatch, capsys):
    _patch_run(monkeypatch)
    for k in ("GRIN_MODEL_BACKEND", "GRIN_MODEL_URL", "GRIN_MODEL_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    cli.main(["engage", _eng_yaml(tmp_path), "--goal", "x"])
    err = capsys.readouterr().err.lower()
    assert "[backend]" in err and "local" in err


def test_notice_shows_cloud(tmp_path, monkeypatch, capsys):
    _patch_run(monkeypatch)
    monkeypatch.setenv("GRIN_MODEL_URL", "https://api.deepseek.com")
    monkeypatch.setenv("GRIN_MODEL_API_KEY", "sk-x")
    monkeypatch.delenv("GRIN_MODEL_BACKEND", raising=False)
    cli.main(["engage", _eng_yaml(tmp_path), "--goal", "x"])
    err = capsys.readouterr().err.lower()
    assert "[backend]" in err and "cloud" in err and "deepseek-chat" in err
