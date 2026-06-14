from ronin.inference import FakeClient, InferenceClient, OllamaClient


def test_fake_client_single_reply_repeats():
    c: InferenceClient = FakeClient("hello")
    assert c.is_up() is True
    assert c.generate(model="m", system="s", prompt="p") == "hello"
    assert c.generate(model="m", system="s", prompt="p") == "hello"


def test_fake_client_returns_reply_sequence_then_sticks_on_last():
    c = FakeClient(["one", "two"])
    assert c.generate(model="m", system="s", prompt="p") == "one"
    assert c.generate(model="m", system="s", prompt="p") == "two"
    assert c.generate(model="m", system="s", prompt="p") == "two"   # sticks on last


def test_fake_client_down_and_models():
    c = FakeClient("x", up=False, models=["qwen3:14b"])
    assert c.is_up() is False
    assert c.installed_models() == ["qwen3:14b"]


def test_ollama_client_disables_thinking(monkeypatch):
    captured = {}

    class _Resp:
        def raise_for_status(self): ...
        def json(self): return {"response": "ok"}

    def fake_post(url, json, timeout):
        captured["body"] = json
        return _Resp()

    monkeypatch.setattr("ronin.inference.httpx.post", fake_post)
    out = OllamaClient().generate(model="qwen3:8b", system="s", prompt="p")
    assert out == "ok"
    assert captured["body"]["think"] is False        # thinking disabled for speed
    assert captured["body"]["model"] == "qwen3:8b"
