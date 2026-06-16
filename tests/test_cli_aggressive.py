from grin import cli


def _write_eng(tmp_path):
    import yaml
    from grin.lab.engagements import engagement_dict
    from grin.lab.answers import Target
    t = Target("t1-ssh", "grin-lab-ssh", "172.30.0.11", "easy", [22],
               "weak-credentials", ["ssh weak credentials"], "GRIN{a}", "flag-in-loot")
    p = tmp_path / "e.yaml"
    p.write_text(yaml.safe_dump(engagement_dict(t)))
    return str(p)


def test_engage_aggressive_flag_passes_through(tmp_path, monkeypatch):
    captured = {}
    def fake_orchestrate(eng, **kw):
        captured.update(kw)
        from grin.orchestrator import EngagementResult
        return EngagementResult("completed", [], [], [], [], goal=kw.get("goal", ""))
    monkeypatch.setattr(cli, "orchestrate", fake_orchestrate)
    monkeypatch.setattr(cli, "save_result", lambda *a, **k: None)
    rc = cli.main(["engage", _write_eng(tmp_path), "--goal", "x", "--aggressive"])
    assert rc == 0
    assert captured.get("aggressive") is True
    assert captured.get("catalog") is not None


def test_engage_without_flag_not_aggressive(tmp_path, monkeypatch):
    captured = {}
    def fake_orchestrate(eng, **kw):
        captured.update(kw)
        from grin.orchestrator import EngagementResult
        return EngagementResult("completed", [], [], [], [], goal=kw.get("goal", ""))
    monkeypatch.setattr(cli, "orchestrate", fake_orchestrate)
    monkeypatch.setattr(cli, "save_result", lambda *a, **k: None)
    rc = cli.main(["engage", _write_eng(tmp_path), "--goal", "x"])
    assert rc == 0
    assert captured.get("aggressive") in (False, None)
    assert captured.get("catalog") is None


def _write_eng_strength(tmp_path, level):
    import yaml
    doc = {"id": "s", "name": "s", "mode": "adhoc", "scope": {"in": ["t"]},
           "roe": {"allowed_actions": ["passive", "active-scan", "exploit"]},
           "autonomy": "autonomous", "env": {"kind": "local"},
           "audit_log": str(tmp_path / "a.jsonl"), "state": "active", "strength": level}
    p = tmp_path / "e.yaml"; p.write_text(yaml.safe_dump(doc))
    return str(p)


def test_engage_honors_yaml_strength_aggressive(tmp_path, monkeypatch):
    captured = {}
    def fake_orchestrate(eng, **kw):
        captured.update(kw)
        from grin.orchestrator import EngagementResult
        return EngagementResult("completed", [], [], [], [], goal=kw.get("goal", ""))
    monkeypatch.setattr(cli, "orchestrate", fake_orchestrate)
    monkeypatch.setattr(cli, "save_result", lambda *a, **k: None)
    rc = cli.main(["engage", _write_eng_strength(tmp_path, "aggressive"), "--goal", "x"])
    assert rc == 0
    assert captured.get("aggressive") is True          # strength=aggressive triggers the sweep
    assert captured.get("max_objectives") >= 24        # strength budget floor applied


def test_engage_yaml_strength_normal_not_aggressive(tmp_path, monkeypatch):
    captured = {}
    def fake_orchestrate(eng, **kw):
        captured.update(kw)
        from grin.orchestrator import EngagementResult
        return EngagementResult("completed", [], [], [], [], goal=kw.get("goal", ""))
    monkeypatch.setattr(cli, "orchestrate", fake_orchestrate)
    monkeypatch.setattr(cli, "save_result", lambda *a, **k: None)
    cli.main(["engage", _write_eng_strength(tmp_path, "normal"), "--goal", "x"])
    assert captured.get("aggressive") in (False, None)
