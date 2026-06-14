def test_launch_without_pyqt_returns_hint(monkeypatch, capsys):
    """If PyQt6 isn't installed, `grin app` must fail soft with the install hint."""
    import builtins
    import sys
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
