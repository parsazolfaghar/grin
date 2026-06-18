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


def test_generate_retries_on_429_then_succeeds(monkeypatch):
    # Free tiers (Cerebras/Groq/OpenRouter) 429 under Grin's call rate — the client must back off and
    # retry instead of crashing the engagement. Two 429s then a 200 should yield the content.
    seq = [_Resp({}, 429), _Resp({}, 429),
           _Resp({"choices": [{"message": {"content": "pong"}}]}, 200)]
    calls = {"n": 0}
    def fake_post(*a, **k):
        r = seq[calls["n"]]; calls["n"] += 1; return r
    monkeypatch.setattr(inf.httpx, "post", fake_post)
    slept = []
    c = OpenAICompatClient("https://x", "k", sleep=lambda s: slept.append(s))
    assert c.generate(model="m", system="s", prompt="p") == "pong"
    assert calls["n"] == 3 and len(slept) == 2   # retried twice, then succeeded


def test_generate_gives_up_after_max_retries(monkeypatch):
    # Persistent 429 eventually raises (bounded) rather than looping forever.
    monkeypatch.setattr(inf.httpx, "post", lambda *a, **k: _Resp({}, 429))
    c = OpenAICompatClient("https://x", "k", max_retries=3, sleep=lambda s: None)
    with pytest.raises(RuntimeError):
        c.generate(model="m", system="s", prompt="p")


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
