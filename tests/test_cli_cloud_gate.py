import json
from grin import cli


def _eng_yaml(tmp_path, mode):
    import yaml
    d = {"id": "e", "name": "n", "mode": mode,
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


def _markers(audit_path):
    from pathlib import Path
    p = Path(audit_path)
    if not p.exists():
        return []
    out = []
    for ln in p.read_text().splitlines():
        ln = ln.strip()
        if ln:
            r = json.loads(ln)
            if r.get("event") == "model-backend":
                out.append(r)
    return out


def test_cloud_client_warns_and_audits(tmp_path, monkeypatch, capsys):
    _patch_run(monkeypatch)
    monkeypatch.setenv("GRIN_MODEL_BACKEND", "openai")
    monkeypatch.setenv("GRIN_MODEL_URL", "https://api.deepseek.com")
    monkeypatch.setenv("GRIN_MODEL_API_KEY", "sk-x")
    path = _eng_yaml(tmp_path, "client")
    rc = cli.main(["engage", path, "--goal", "x"])
    assert rc == 0
    err = capsys.readouterr().err.lower()
    assert "third-party" in err or "warning" in err
    from grin.engagement import load_engagement
    m = _markers(load_engagement(path).audit_log)
    assert m and m[0]["backend"] == "openai"


def test_cloud_ownlab_audits_no_warning(tmp_path, monkeypatch, capsys):
    _patch_run(monkeypatch)
    monkeypatch.setenv("GRIN_MODEL_BACKEND", "openai")
    monkeypatch.setenv("GRIN_MODEL_URL", "https://api.deepseek.com")
    monkeypatch.setenv("GRIN_MODEL_API_KEY", "sk-x")
    path = _eng_yaml(tmp_path, "own-lab")
    cli.main(["engage", path, "--goal", "x"])
    err = capsys.readouterr().err.lower()
    assert "third-party" not in err
    from grin.engagement import load_engagement
    assert _markers(load_engagement(path).audit_log)


def test_local_backend_no_marker_no_warning(tmp_path, monkeypatch, capsys):
    _patch_run(monkeypatch)
    monkeypatch.delenv("GRIN_MODEL_BACKEND", raising=False)
    path = _eng_yaml(tmp_path, "client")
    cli.main(["engage", path, "--goal", "x"])
    err = capsys.readouterr().err.lower()
    assert "third-party" not in err
    from grin.engagement import load_engagement
    assert _markers(load_engagement(path).audit_log) == []
