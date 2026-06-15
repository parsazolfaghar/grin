"""Local-model boundary — recycled from the Sensei (app/inference.py). A Protocol with a
real Ollama client and a deterministic fake. The Executor talks only to this interface, so
the whole loop is testable with no model. Local-only by project charter."""
import os
from typing import Protocol
import httpx

OLLAMA_URL = "http://127.0.0.1:11434"


def resolve_ollama_url(explicit: str | None = None) -> str:
    """Where to reach Ollama: an explicit arg wins, else $GRIN_OLLAMA_URL, else local default.
    The deployment-mode toggle (roadmap R4) sets $GRIN_OLLAMA_URL to point the Mac at the rig
    (ideally via an SSH tunnel to localhost). One resolver so engine/bench/doctor agree."""
    return explicit or os.environ.get("GRIN_OLLAMA_URL") or OLLAMA_URL


class InferenceClient(Protocol):
    def is_up(self) -> bool: ...
    def installed_models(self) -> list[str]: ...
    def generate(self, model: str, system: str, prompt: str, temperature: float = 0.3,
                 keep_alive: str = "10m") -> str: ...


class OllamaClient:
    """Real client — talks to a local Ollama on the rig. Not exercised in unit tests."""

    def __init__(self, base_url: str | None = None, timeout: float = 600.0):
        self.base_url = resolve_ollama_url(base_url)
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


def active_backend() -> str:
    """Resolve the model backend. Cloud-default when configured: an explicit GRIN_MODEL_BACKEND
    (ollama|openai) always wins; otherwise cloud ('openai') if BOTH GRIN_MODEL_URL and
    GRIN_MODEL_API_KEY are set, else local Ollama. No network probe here — reachability is surfaced
    by is_up()/`grin doctor`."""
    explicit = os.environ.get("GRIN_MODEL_BACKEND", "").lower()
    if explicit in ("openai", "ollama"):
        return explicit
    if os.environ.get("GRIN_MODEL_URL") and os.environ.get("GRIN_MODEL_API_KEY"):
        return "openai"
    return "ollama"


class OpenAICompatClient:
    """An OpenAI-compatible chat client (DeepSeek, OpenRouter, Groq, Gemini-compat, rented vLLM...).
    Implements the same InferenceClient Protocol as OllamaClient so the engine is unchanged.
    Cloud is opt-in by project charter; client-data exposure is warned + audited by the cli."""

    def __init__(self, base_url: str, api_key: str, timeout: float = 600.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

    def is_up(self) -> bool:
        try:
            return httpx.get(f"{self.base_url}/models", headers=self._headers(),
                             timeout=5.0).status_code == 200
        except httpx.HTTPError:
            return False

    def installed_models(self) -> list[str]:
        try:
            data = httpx.get(f"{self.base_url}/models", headers=self._headers(), timeout=5.0).json()
            return [m.get("id", "") for m in data.get("data", []) if m.get("id")]
        except httpx.HTTPError:
            return []

    def generate(self, model: str, system: str, prompt: str, temperature: float = 0.3,
                 keep_alive: str = "10m") -> str:
        body = {"model": model, "stream": False, "temperature": temperature,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": prompt}]}
        r = httpx.post(f"{self.base_url}/chat/completions", json=body, headers=self._headers(),
                       timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        try:
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            return ""


def make_inference_client():
    """Build the active model client from env. Local Ollama is the default; GRIN_MODEL_BACKEND=openai
    selects the cloud client (requires GRIN_MODEL_URL + GRIN_MODEL_API_KEY). One factory so engine,
    bench and doctor agree on the backend."""
    if active_backend() == "openai":
        url = os.environ.get("GRIN_MODEL_URL")
        key = os.environ.get("GRIN_MODEL_API_KEY")
        if not url or not key:
            raise ValueError("GRIN_MODEL_BACKEND=openai requires GRIN_MODEL_URL and GRIN_MODEL_API_KEY")
        return OpenAICompatClient(base_url=url, api_key=key)
    return OllamaClient()


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
