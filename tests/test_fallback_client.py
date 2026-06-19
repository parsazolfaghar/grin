import httpx
import pytest

from grin.inference import FakeClient, FallbackClient


class _Boom:
    """A client that is_up but always errors on generate — stands in for a provider that 500s /
    rate-limits past its retries."""
    def __init__(self):
        self.calls = 0

    def is_up(self):
        return True

    def installed_models(self):
        return []

    def generate(self, model, system, prompt, temperature=0.3, keep_alive="10m"):
        self.calls += 1
        raise httpx.HTTPError("boom")


def test_uses_first_healthy_client():
    primary = FakeClient("PRIMARY")
    secondary = FakeClient("SECONDARY")
    fb = FallbackClient([primary, secondary])
    assert fb.generate("m", "s", "p") == "PRIMARY"


def test_skips_a_down_client():
    down = FakeClient("DOWN", up=False)
    up = FakeClient("UP")
    fb = FallbackClient([down, up])
    assert fb.generate("m", "s", "p") == "UP"


def test_falls_through_on_generate_error():
    boom = _Boom()
    backup = FakeClient("BACKUP")
    fb = FallbackClient([boom, backup])
    assert fb.generate("m", "s", "p") == "BACKUP"
    assert boom.calls == 1   # it was tried, then we moved on


def test_is_up_true_if_any_client_up():
    fb = FallbackClient([FakeClient(up=False), FakeClient(up=True)])
    assert fb.is_up() is True
    fb2 = FallbackClient([FakeClient(up=False), FakeClient(up=False)])
    assert fb2.is_up() is False


def test_all_failing_reraises_last_error():
    fb = FallbackClient([_Boom(), _Boom()])
    with pytest.raises(httpx.HTTPError):
        fb.generate("m", "s", "p")


def test_empty_client_list_is_rejected():
    with pytest.raises(ValueError):
        FallbackClient([])


def _cloud_env(monkeypatch):
    monkeypatch.setenv("GRIN_MODEL_BACKEND", "openai")
    monkeypatch.setenv("GRIN_MODEL_URL", "https://api.primary/v1")
    monkeypatch.setenv("GRIN_MODEL_API_KEY", "k1")
    monkeypatch.delenv("GRIN_MODEL_FALLBACK_URL", raising=False)
    monkeypatch.delenv("GRIN_MODEL_FALLBACK_API_KEY", raising=False)


def test_factory_wraps_cloud_with_secondary_cloud_fallback(monkeypatch):
    # Cloud-only deployment: the useful fallback is a SECOND provider, not local.
    from grin.inference import OpenAICompatClient, make_inference_client
    _cloud_env(monkeypatch)
    monkeypatch.setenv("GRIN_MODEL_FALLBACK_URL", "https://api.backup/v1")
    monkeypatch.setenv("GRIN_MODEL_FALLBACK_API_KEY", "k2")
    c = make_inference_client()
    assert isinstance(c, FallbackClient)
    inner = c._clients
    assert len(inner) == 2 and all(isinstance(x, OpenAICompatClient) for x in inner)
    assert inner[0].base_url.endswith("primary/v1") and inner[1].base_url.endswith("backup/v1")


def test_factory_cloud_only_by_default(monkeypatch):
    from grin.inference import OpenAICompatClient, make_inference_client
    _cloud_env(monkeypatch)
    c = make_inference_client()
    assert isinstance(c, OpenAICompatClient) and not isinstance(c, FallbackClient)
