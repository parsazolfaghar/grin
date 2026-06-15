import importlib.util
import sys
from pathlib import Path


def _load_app():
    path = Path(__file__).resolve().parents[1] / "lab" / "app" / "app.py"
    spec = importlib.util.spec_from_file_location("lab_app", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["lab_app"] = mod
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
