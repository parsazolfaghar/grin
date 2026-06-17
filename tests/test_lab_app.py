import importlib.util
import sys
from pathlib import Path


def _load_app(filename="app.py", modname="lab_app"):
    path = Path(__file__).resolve().parents[1] / "lab" / "app" / filename
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod.app


def test_index_serves_form():
    client = _load_app().test_client()
    r = client.get("/")
    assert r.status_code == 200
    assert b"host" in r.data.lower()


def test_ping_is_command_injectable():
    # The planted vuln: input is passed to a shell unsanitised, so `;` chains a command.
    client = _load_app().test_client()
    r = client.post("/ping", data={"host": "127.0.0.1; echo INJECTED_MARKER"})
    assert r.status_code == 200
    assert b"INJECTED_MARKER" in r.data


def test_t4_view_is_path_traversable(tmp_path, monkeypatch):
    # T4: /view joins user input to BASE without sanitisation -> ../ reads outside the base dir.
    _load_app("app_traversal.py", "lab_app_t4")   # registers the module in sys.modules
    # point BASE at a temp dir and plant a "secret" one level up to prove traversal
    import lab_app_t4 as m
    base = tmp_path / "files"; base.mkdir()
    (tmp_path / "secret.txt").write_text("devops:$6$deadbeef")
    monkeypatch.setattr(m, "BASE", str(base))
    client = m.app.test_client()
    r = client.get("/view?file=../secret.txt")
    assert r.status_code == 200
    assert b"devops:$6$deadbeef" in r.data


def test_t5_name_is_ssti():
    # T5: the name param is rendered as template source -> {{7*7}} evaluates server-side.
    client = _load_app("app_ssti.py", "lab_app_t5").test_client()
    r = client.get("/?name={{7*7}}")
    assert r.status_code == 200
    assert b"Hello, 49!" in r.data
