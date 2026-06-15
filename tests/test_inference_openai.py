import pytest
import grin.inference as inf
from grin.inference import OpenAICompatClient, make_inference_client, active_backend, OllamaClient


class _Resp:
    def __init__(self, payload, status=200):
        self._p = payload
        self.status_code = status
    def json(self):
        return self._p
    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"http {self.status_code}")


def test_generate_posts_chat_completions_and_parses(monkeypatch):
    captured = {}
    def fake_post(url, json=None, headers=None, timeout=None):
        captured["url"] = url; captured["json"] = json; captured["headers"] = headers
        return _Resp({"choices": [{"message": {"content": "pong"}}]})
    monkeypatch.setattr(inf.httpx, "post", fake_post)
    c = OpenAICompatClient(base_url="https://api.deepseek.com", api_key="sk-x")
    out = c.generate(model="deepseek-chat", system="sys", prompt="hi", temperature=0.0)
    assert out == "pong"
    assert captured["url"] == "https://api.deepseek.com/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer sk-x"
    msgs = captured["json"]["messages"]
    assert msgs[0] == {"role": "system", "content": "sys"}
    assert msgs[1] == {"role": "user", "content": "hi"}
    assert captured["json"]["model"] == "deepseek-chat"
    assert captured["json"]["stream"] is False


def test_generate_malformed_returns_empty(monkeypatch):
    monkeypatch.setattr(inf.httpx, "post", lambda *a, **k: _Resp({"nope": 1}))
    c = OpenAICompatClient("https://x", "k")
    assert c.generate(model="m", system="s", prompt="p") == ""


def test_is_up(monkeypatch):
    monkeypatch.setattr(inf.httpx, "get", lambda *a, **k: _Resp({"data": []}, 200))
    assert OpenAICompatClient("https://x", "k").is_up() is True
    monkeypatch.setattr(inf.httpx, "get", lambda *a, **k: (_ for _ in ()).throw(inf.httpx.HTTPError("x")))
    assert OpenAICompatClient("https://x", "k").is_up() is False


def test_installed_models(monkeypatch):
    monkeypatch.setattr(inf.httpx, "get",
                        lambda *a, **k: _Resp({"data": [{"id": "deepseek-chat"}, {"id": "deepseek-reasoner"}]}))
    assert OpenAICompatClient("https://x", "k").installed_models() == ["deepseek-chat", "deepseek-reasoner"]


def test_factory_defaults_ollama(monkeypatch):
    monkeypatch.delenv("GRIN_MODEL_BACKEND", raising=False)
    assert isinstance(make_inference_client(), OllamaClient)
    assert active_backend() == "ollama"


def test_factory_openai(monkeypatch):
    monkeypatch.setenv("GRIN_MODEL_BACKEND", "openai")
    monkeypatch.setenv("GRIN_MODEL_URL", "https://api.deepseek.com")
    monkeypatch.setenv("GRIN_MODEL_API_KEY", "sk-x")
    c = make_inference_client()
    assert isinstance(c, OpenAICompatClient)
    assert active_backend() == "openai"


def test_factory_openai_missing_config_raises(monkeypatch):
    monkeypatch.setenv("GRIN_MODEL_BACKEND", "openai")
    monkeypatch.delenv("GRIN_MODEL_URL", raising=False)
    monkeypatch.delenv("GRIN_MODEL_API_KEY", raising=False)
    with pytest.raises(ValueError):
        make_inference_client()
