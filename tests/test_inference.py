from ronin.inference import FakeClient, InferenceClient


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
