from grin.inference import OllamaClient, resolve_ollama_url, OLLAMA_URL


def test_default_is_localhost(monkeypatch):
    monkeypatch.delenv("GRIN_OLLAMA_URL", raising=False)
    assert resolve_ollama_url() == OLLAMA_URL
    assert OllamaClient().base_url == OLLAMA_URL


def test_env_var_redirects_endpoint(monkeypatch):
    monkeypatch.setenv("GRIN_OLLAMA_URL", "http://127.0.0.1:9999")
    assert resolve_ollama_url() == "http://127.0.0.1:9999"
    assert OllamaClient().base_url == "http://127.0.0.1:9999"  # engine honors it (deployment toggle)


def test_explicit_arg_wins_over_env(monkeypatch):
    monkeypatch.setenv("GRIN_OLLAMA_URL", "http://from-env:11434")
    assert resolve_ollama_url("http://explicit:11434") == "http://explicit:11434"
    assert OllamaClient("http://explicit:11434").base_url == "http://explicit:11434"


def test_doctor_ollama_check_shows_endpoint():
    from grin.doctor import check_ollama
    from grin.inference import FakeClient
    fc = FakeClient(up=True)
    fc.base_url = "http://rig:11434"
    c = check_ollama(fc)
    assert c.status == "ok" and "http://rig:11434" in c.detail
