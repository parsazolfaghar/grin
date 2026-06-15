from grin.doctor import check_model_backend


class _Client:
    def __init__(self, up):
        self._up = up
    def is_up(self):
        return self._up


def test_cloud_ok(monkeypatch):
    monkeypatch.setenv("GRIN_MODEL_API_KEY", "sk-x")
    assert check_model_backend(_Client(True), "openai").status == "ok"


def test_cloud_broken_no_key(monkeypatch):
    monkeypatch.delenv("GRIN_MODEL_API_KEY", raising=False)
    assert check_model_backend(_Client(True), "openai").status == "broken"


def test_cloud_broken_unreachable(monkeypatch):
    monkeypatch.setenv("GRIN_MODEL_API_KEY", "sk-x")
    assert check_model_backend(_Client(False), "openai").status == "broken"


def test_ollama_delegates():
    assert check_model_backend(_Client(True), "ollama").status == "ok"
