from grin.app import launch

def test_web_dir_exists_and_has_index():
    import os
    assert os.path.exists(os.path.join(launch.web_dir(), "index.html"))
    assert os.path.exists(os.path.join(launch.web_dir(), "app.css"))

def test_launch_without_webview_returns_hint(monkeypatch, capsys):
    # simulate pywebview missing
    import builtins
    real_import = builtins.__import__
    def fake_import(name, *a, **k):
        if name == "webview":
            raise ImportError("no webview")
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", fake_import)
    rc = launch.main([])
    out = capsys.readouterr().out + capsys.readouterr().err
    assert rc == 1
