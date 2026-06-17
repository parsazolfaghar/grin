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


def test_make_client_uses_factory(monkeypatch):
    monkeypatch.setenv("GRIN_MODEL_BACKEND", "openai")
    monkeypatch.setenv("GRIN_MODEL_URL", "https://api.deepseek.com")
    monkeypatch.setenv("GRIN_MODEL_API_KEY", "sk-x")
    from grin.inference import OpenAICompatClient
    assert isinstance(cli._make_client(None), OpenAICompatClient)
