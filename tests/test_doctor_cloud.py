from grin.doctor import check_model_backend


class _Client:
    """A stand-in for the passed-in (Ollama) client. For the openai backend the check ignores this
    and probes the cloud client built by make_inference_client — so its is_up must not decide health."""
    def __init__(self, up):
        self._up = up
    def is_up(self):
        return self._up


class _Cloud:
    def __init__(self, up):
        self._up = up
    def is_up(self):
        return self._up


def test_cloud_ok(monkeypatch):
    monkeypatch.setenv("GRIN_MODEL_API_KEY", "sk-x")
    monkeypatch.setattr("grin.inference.make_inference_client", lambda *a, **k: _Cloud(True))
    # passed-in client is DOWN, but the cloud probe is UP -> ok
    assert check_model_backend(_Client(False), "openai").status == "ok"


def test_cloud_broken_no_key(monkeypatch):
    monkeypatch.delenv("GRIN_MODEL_API_KEY", raising=False)
    assert check_model_backend(_Client(True), "openai").status == "broken"


def test_cloud_broken_unreachable(monkeypatch):
    monkeypatch.setenv("GRIN_MODEL_API_KEY", "sk-x")
    monkeypatch.setattr("grin.inference.make_inference_client", lambda *a, **k: _Cloud(False))
    assert check_model_backend(_Client(True), "openai").status == "broken"


def test_cloud_build_error_is_broken(monkeypatch):
    monkeypatch.setenv("GRIN_MODEL_API_KEY", "sk-x")
    def boom(*a, **k):
        raise ValueError("no url")
    monkeypatch.setattr("grin.inference.make_inference_client", boom)
    assert check_model_backend(_Client(True), "openai").status == "broken"


def test_ollama_delegates():
    assert check_model_backend(_Client(True), "ollama").status == "ok"
