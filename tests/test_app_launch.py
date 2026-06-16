def test_resolve_engagements_dir_explicit_arg_wins(monkeypatch):
    """An explicit positional arg beats env and any fallback."""
    monkeypatch.setenv("GRIN_ENGAGEMENTS", "/from/env")
    from grin.app.launch import resolve_engagements_dir
    assert resolve_engagements_dir(["/explicit/path"]) == "/explicit/path"


def test_resolve_engagements_dir_uses_env(monkeypatch):
    """With no arg, $GRIN_ENGAGEMENTS is used."""
    monkeypatch.setenv("GRIN_ENGAGEMENTS", "/from/env")
    from grin.app.launch import resolve_engagements_dir
    assert resolve_engagements_dir([]) == "/from/env"


def test_resolve_engagements_dir_falls_back_to_existing_dir(monkeypatch, tmp_path):
    """No arg, no env -> first existing of the candidate dirs."""
    import os
    monkeypatch.delenv("GRIN_ENGAGEMENTS", raising=False)
    cand = tmp_path / "examples"
    cand.mkdir()
    monkeypatch.setattr(os.path, "expanduser",
                        lambda p: str(cand) if p == "~/grin/examples" else "/nope/missing")
    from grin.app.launch import resolve_engagements_dir
    assert resolve_engagements_dir([]) == str(cand)


def test_resolve_engagements_dir_defaults_to_dot(monkeypatch):
    """No arg, no env, no candidate dir exists -> '.'."""
    import os
    monkeypatch.delenv("GRIN_ENGAGEMENTS", raising=False)
    monkeypatch.setattr(os.path, "expanduser", lambda p: "/definitely/missing/dir")
    from grin.app.launch import resolve_engagements_dir
    assert resolve_engagements_dir([]) == "."


def test_launch_without_pyqt_returns_hint(monkeypatch, capsys, tmp_path):
    """If PyQt6 isn't installed, `grin app` must fail soft with the install hint."""
    import builtins
    import sys
    monkeypatch.setenv("GRIN_APP_LOG", str(tmp_path / "app.log"))  # don't pollute the real ~/.grin log
    monkeypatch.delitem(sys.modules, "grin.app.qt_app", raising=False)
    monkeypatch.delitem(sys.modules, "PyQt6", raising=False)
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "PyQt6" or name.startswith("PyQt6."):
            raise ImportError("no PyQt6")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    from grin.app import launch
    rc = launch.main([])
    cap = capsys.readouterr()
    assert rc == 1
    assert "grin[app]" in (cap.out + cap.err)  # the install hint is surfaced
