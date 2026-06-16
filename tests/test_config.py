import os
from grin.config import load_env_file, DEFAULT_ENV_PATH


def test_default_path_under_dot_grin():
    assert ".grin" in DEFAULT_ENV_PATH and DEFAULT_ENV_PATH.endswith("env")


def test_parses_export_and_plain(tmp_path, monkeypatch):
    for k in ("FOO", "BAR", "BAZ"):
        monkeypatch.delenv(k, raising=False)
    p = tmp_path / "env"
    p.write_text("# a comment\n\nexport FOO=hello\nBAR=\"quoted val\"\n  BAZ=3 \n")
    got = load_env_file(str(p))
    assert os.environ["FOO"] == "hello"
    assert os.environ["BAR"] == "quoted val"
    assert os.environ["BAZ"] == "3"
    assert got == {"FOO": "hello", "BAR": "quoted val", "BAZ": "3"}


def test_does_not_override_real_env(tmp_path, monkeypatch):
    monkeypatch.setenv("FOO", "real")
    p = tmp_path / "env"
    p.write_text("FOO=fromfile\n")
    got = load_env_file(str(p))
    assert os.environ["FOO"] == "real"
    assert "FOO" not in got


def test_missing_file_is_noop(tmp_path):
    assert load_env_file(str(tmp_path / "nope")) == {}


def test_garbage_lines_skipped(tmp_path, monkeypatch):
    monkeypatch.delenv("OK", raising=False)
    p = tmp_path / "env"
    p.write_text("not a kv line\n=noname\nOK=1\n")
    got = load_env_file(str(p))
    assert got == {"OK": "1"}
