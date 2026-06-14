"""Local-model boundary — recycled from the Sensei (app/inference.py). A Protocol with a
real Ollama client and a deterministic fake. The Executor talks only to this interface, so
the whole loop is testable with no model. Local-only by project charter."""
from typing import Protocol
import httpx

OLLAMA_URL = "http://127.0.0.1:11434"


class InferenceClient(Protocol):
    def is_up(self) -> bool: ...
    def installed_models(self) -> list[str]: ...
    def generate(self, model: str, system: str, prompt: str, temperature: float = 0.3,
                 keep_alive: str = "10m") -> str: ...


class OllamaClient:
    """Real client — talks to a local Ollama on the rig. Not exercised in unit tests."""

    def __init__(self, base_url: str = OLLAMA_URL, timeout: float = 600.0):
        self.base_url = base_url
        self.timeout = timeout

    def is_up(self) -> bool:
        try:
            return httpx.get(f"{self.base_url}/api/tags", timeout=2.0).status_code == 200
        except httpx.HTTPError:
            return False

    def installed_models(self) -> list[str]:
        try:
            data = httpx.get(f"{self.base_url}/api/tags", timeout=5.0).json()
            return [m["name"] for m in data.get("models", [])]
        except httpx.HTTPError:
            return []

    def generate(self, model: str, system: str, prompt: str, temperature: float = 0.3,
                 keep_alive: str = "10m") -> str:
        # Free-text (no grammar-constrained JSON mode): Ollama's JSON mode degrades GGUF
        # security models into empty output; tolerant parsing handles free text instead.
        # think=False disables "thinking" mode on reasoning models (e.g. qwen3): an autonomous
        # tool driving many steps doesn't want minutes of per-step reasoning, and it returns the
        # clean answer directly. Accepted + harmless (no-op) for non-thinking models.
        body = {"model": model, "system": system, "prompt": prompt, "stream": False,
                "think": False, "options": {"temperature": temperature},
                "keep_alive": keep_alive}
        r = httpx.post(f"{self.base_url}/api/generate", json=body, timeout=self.timeout)
        r.raise_for_status()
        return r.json().get("response", "")


class FakeClient:
    """Deterministic stand-in for tests + the Mac. Accepts a single reply or a SEQUENCE of
    replies (one per loop turn); after the last it sticks (so an over-long loop is bounded
    by the executor's step budget, not by running out of replies)."""

    def __init__(self, replies="", up: bool = True, models: list[str] | None = None):
        self._replies = [replies] if isinstance(replies, str) else list(replies) or [""]
        self._i = 0
        self._up = up
        self._models = models or []

    def is_up(self) -> bool:
        return self._up

    def installed_models(self) -> list[str]:
        return list(self._models)

    def generate(self, model: str, system: str, prompt: str, temperature: float = 0.3,
                 keep_alive: str = "10m") -> str:
        reply = self._replies[min(self._i, len(self._replies) - 1)]
        self._i += 1
        return reply
