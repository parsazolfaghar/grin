from grin.inference import active_backend


def _clear(monkeypatch):
    for k in ("GRIN_MODEL_BACKEND", "GRIN_MODEL_URL", "GRIN_MODEL_API_KEY"):
        monkeypatch.delenv(k, raising=False)


def test_unset_no_cloud_is_local(monkeypatch):
    _clear(monkeypatch)
    assert active_backend() == "ollama"


def test_unset_cloud_configured_is_openai(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("GRIN_MODEL_URL", "https://api.deepseek.com")
    monkeypatch.setenv("GRIN_MODEL_API_KEY", "sk-x")
    assert active_backend() == "openai"


def test_unset_partial_cloud_is_local(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("GRIN_MODEL_URL", "https://api.deepseek.com")
    assert active_backend() == "ollama"


def test_explicit_ollama_wins_over_configured_cloud(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("GRIN_MODEL_URL", "https://api.deepseek.com")
    monkeypatch.setenv("GRIN_MODEL_API_KEY", "sk-x")
    monkeypatch.setenv("GRIN_MODEL_BACKEND", "ollama")
    assert active_backend() == "ollama"


def test_explicit_openai_wins(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("GRIN_MODEL_BACKEND", "openai")
    assert active_backend() == "openai"
