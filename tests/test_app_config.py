import json
import os

from grin.app import config


def test_defaults_when_no_file(tmp_path):
    p = str(tmp_path / "app.json")
    data = config.load(p)
    assert data["active"] == "local"
    assert set(data["profiles"]) >= {"local", "split"}
    assert data["profiles"]["split"]["env"]["kind"] == "ssh"


def test_set_active_persists_round_trip(tmp_path):
    p = str(tmp_path / "app.json")
    config.set_active("split", p)
    assert json.load(open(p))["active"] == "split"
    name, prof = config.get_active(p)
    assert name == "split" and prof["ollama_url"].startswith("http")


def test_set_active_unknown_raises(tmp_path):
    p = str(tmp_path / "app.json")
    try:
        config.set_active("nope", p)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_next_profile_cycles():
    assert config.next_profile("local") == "split"
    assert config.next_profile("split") == "local"


def test_apply_profile_sets_env_and_returns_tool_env(monkeypatch):
    monkeypatch.delenv("GRIN_OLLAMA_URL", raising=False)
    env = config.apply_profile(config.DEFAULT_PROFILES["split"])
    assert os.environ["GRIN_OLLAMA_URL"] == config.DEFAULT_PROFILES["split"]["ollama_url"]
    assert env["kind"] == "ssh"


def test_apply_active_uses_persisted_choice(tmp_path, monkeypatch):
    monkeypatch.delenv("GRIN_OLLAMA_URL", raising=False)
    p = str(tmp_path / "app.json")
    config.set_active("split", p)
    env = config.apply_active(p)
    assert env["kind"] == "ssh"
    assert "your-rig" in os.environ["GRIN_OLLAMA_URL"]
