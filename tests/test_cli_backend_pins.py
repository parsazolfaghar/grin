from grin import cli


def test_resolve_pins_ollama(monkeypatch):
    monkeypatch.delenv("GRIN_MODEL_BACKEND", raising=False)
    pins = cli._resolve_pins(planner=None, recon=None, exploit=None)
    assert pins["planner"] == cli.DEFAULT_PINS["planner"]
    assert pins["exploit"] == cli.DEFAULT_PINS["exploit"]


def test_resolve_pins_openai(monkeypatch):
    monkeypatch.setenv("GRIN_MODEL_BACKEND", "openai")
    pins = cli._resolve_pins(planner=None, recon=None, exploit=None)
    assert pins["planner"] == cli.CLOUD_DEFAULT_PINS["planner"] == "deepseek-reasoner"
    assert pins["recon"] == "deepseek-chat" and pins["exploit"] == "deepseek-chat"


def test_resolve_pins_explicit_wins(monkeypatch):
    monkeypatch.setenv("GRIN_MODEL_BACKEND", "openai")
    pins = cli._resolve_pins(planner="deepseek-reasoner", recon=None, exploit=None)
    assert pins["planner"] == "deepseek-reasoner"
    assert pins["recon"] == "deepseek-chat"


def test_resolve_pins_env_override(monkeypatch):
    # GRIN_*_MODEL (e.g. set in ~/.grin/env) selects the model per role, so the env file alone can
    # point a non-DeepSeek cloud backend (Cerebras) at its own model without code edits or CLI flags.
    monkeypatch.setenv("GRIN_MODEL_BACKEND", "openai")
    monkeypatch.setenv("GRIN_PLANNER_MODEL", "zai-glm-4.7")
    monkeypatch.setenv("GRIN_RECON_MODEL", "zai-glm-4.7")
    monkeypatch.setenv("GRIN_EXPLOIT_MODEL", "zai-glm-4.7")
    pins = cli._resolve_pins(planner=None, recon=None, exploit=None)
    assert pins == {"planner": "zai-glm-4.7", "recon": "zai-glm-4.7", "exploit": "zai-glm-4.7"}


def test_resolve_pins_explicit_beats_env(monkeypatch):
    # CLI flag is the strongest signal — it wins over the env override.
    monkeypatch.setenv("GRIN_MODEL_BACKEND", "openai")
    monkeypatch.setenv("GRIN_EXPLOIT_MODEL", "zai-glm-4.7")
    pins = cli._resolve_pins(planner=None, recon=None, exploit="gpt-oss-120b")
    assert pins["exploit"] == "gpt-oss-120b"
    assert pins["recon"] == "deepseek-chat"   # unset role still falls to backend default


def test_make_client_uses_factory(monkeypatch):
    monkeypatch.setenv("GRIN_MODEL_BACKEND", "openai")
    monkeypatch.setenv("GRIN_MODEL_URL", "https://api.deepseek.com")
    monkeypatch.setenv("GRIN_MODEL_API_KEY", "sk-x")
    from grin.inference import OpenAICompatClient
    assert isinstance(cli._make_client(None), OpenAICompatClient)
