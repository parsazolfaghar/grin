import json
import os

from grin.app import config


def test_defaults_when_no_file(tmp_path):
    p = str(tmp_path / "app.json")
    data = config.load(p)
    assert data["active"] == "cloud"
    assert set(data["profiles"]) >= {"cloud", "local", "split"}
    assert data["profiles"]["split"]["env"]["kind"] == "ssh"
    assert data["profiles"]["cloud"]["env"]["kind"] == "arsenal"
    assert data["profiles"]["cloud"]["model_backend"] == "openai"


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
    assert config.next_profile("cloud") == "local"
    assert config.next_profile("local") == "split"
    assert config.next_profile("split") == "cloud"


def test_apply_cloud_profile_pins_backend(monkeypatch):
    monkeypatch.delenv("GRIN_MODEL_BACKEND", raising=False)
    env = config.apply_profile(config.DEFAULT_PROFILES["cloud"])
    assert os.environ["GRIN_MODEL_BACKEND"] == "openai"
    assert env["kind"] == "arsenal"


def test_apply_local_profile_pins_ollama_backend(monkeypatch):
    monkeypatch.setenv("GRIN_MODEL_BACKEND", "openai")   # simulate cloud creds already in env
    config.apply_profile(config.DEFAULT_PROFILES["local"])
    assert os.environ["GRIN_MODEL_BACKEND"] == "ollama"  # local mode is authoritative over the brain


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
