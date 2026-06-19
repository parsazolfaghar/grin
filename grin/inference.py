"""Model boundary — a Protocol with a local Ollama client, an OpenAI-compatible cloud client, a
deterministic fake, and an env-driven factory. Backend is cloud-default when configured
(GRIN_MODEL_URL + GRIN_MODEL_API_KEY), else local Ollama; an explicit GRIN_MODEL_BACKEND overrides.
The engine talks only to this interface, so the whole loop is testable with no model."""
import os
import time
from typing import Protocol
import httpx

OLLAMA_URL = "http://127.0.0.1:11434"
# transient statuses worth retrying: rate limit + gateway/server errors. Free tiers (Cerebras, Groq,
# OpenRouter) return 429 readily under Grin's call rate, so retry-with-backoff = the app keeps working.
_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})


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

    def __init__(self, base_url: str, api_key: str, timeout: float = 600.0,
                 max_retries: int = 5, sleep=time.sleep):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self._sleep = sleep   # injectable for tests

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

    def is_up(self) -> bool:
        try:
            # generous timeout: a frozen (PyInstaller) app's first HTTPS call has a slow cold
            # TLS/DNS init that easily exceeds a 5s budget -> false "model unavailable"
            return httpx.get(f"{self.base_url}/models", headers=self._headers(),
                             timeout=20.0).status_code == 200
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
        for attempt in range(self.max_retries + 1):
            r = httpx.post(f"{self.base_url}/chat/completions", json=body, headers=self._headers(),
                           timeout=self.timeout)
            if r.status_code in _RETRY_STATUS and attempt < self.max_retries:
                self._sleep(self._backoff(r, attempt))   # pace under rate limits instead of crashing
                continue
            break
        r.raise_for_status()
        data = r.json()
        try:
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            return ""

    def _backoff(self, resp, attempt: int) -> float:
        """Honor a numeric Retry-After header if the provider sends one, else exponential backoff
        capped at 30s. Keeps a free-tier 429 from killing an engagement — it just paces itself."""
        try:
            hdr = getattr(resp, "headers", {}) or {}
            val = hdr.get("retry-after") or hdr.get("Retry-After")
            if val is not None:
                return min(float(val), 30.0)
        except (ValueError, TypeError, AttributeError):
            pass
        return min(2.0 ** attempt, 30.0)


def make_inference_client():
    """Build the active model client from env. Local Ollama is the default; GRIN_MODEL_BACKEND=openai
    selects the cloud client (requires GRIN_MODEL_URL + GRIN_MODEL_API_KEY). One factory so engine,
    bench and doctor agree on the backend."""
    if active_backend() == "openai":
        url = os.environ.get("GRIN_MODEL_URL")
        key = os.environ.get("GRIN_MODEL_API_KEY")
        if not url or not key:
            raise ValueError("GRIN_MODEL_BACKEND=openai requires GRIN_MODEL_URL and GRIN_MODEL_API_KEY")
        cloud = OpenAICompatClient(base_url=url, api_key=key)
        # Opt-in resilience for a cloud-only deployment: a SECOND provider as backup so an outage /
        # rate-limit on the primary doesn't kill the engagement. Set GRIN_MODEL_FALLBACK_URL +
        # GRIN_MODEL_FALLBACK_API_KEY. Default (unset) = primary cloud only, unchanged.
        fb_url = os.environ.get("GRIN_MODEL_FALLBACK_URL")
        fb_key = os.environ.get("GRIN_MODEL_FALLBACK_API_KEY")
        if fb_url and fb_key:
            return FallbackClient([cloud, OpenAICompatClient(base_url=fb_url, api_key=fb_key)])
        # Back-compat: GRIN_MODEL_FALLBACK=local still adds a local Ollama backup if one is running.
        if os.environ.get("GRIN_MODEL_FALLBACK", "").strip().lower() in ("local", "ollama"):
            return FallbackClient([cloud, OllamaClient()])
        return cloud
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


class FallbackClient:
    """Tiered brain: try an ordered list of InferenceClients (e.g. cloud primary -> local backup, or
    several providers) and use the first that answers. A provider that is down (is_up False) is
    skipped; one that errors mid-generate (500 / rate-limited past its own retries) falls through to
    the next. This keeps an engagement alive across a provider outage — resilience the other tools
    don't offer. Implements the same Protocol, so the engine is unchanged."""

    def __init__(self, clients: list):
        if not clients:
            raise ValueError("FallbackClient needs at least one client")
        self._clients = list(clients)

    def is_up(self) -> bool:
        return any(self._safe_up(c) for c in self._clients)

    @staticmethod
    def _safe_up(c) -> bool:
        try:
            return bool(c.is_up())
        except Exception:        # noqa: BLE001 - a health check must never crash selection
            return False

    def installed_models(self) -> list:
        for c in self._clients:
            if self._safe_up(c):
                try:
                    return list(c.installed_models())
                except Exception:        # noqa: BLE001
                    continue
        return []

    def generate(self, model: str, system: str, prompt: str, temperature: float = 0.3,
                 keep_alive: str = "10m") -> str:
        last_err: Exception | None = None
        for c in self._clients:
            if not self._safe_up(c):
                continue
            try:
                return c.generate(model, system, prompt, temperature=temperature,
                                  keep_alive=keep_alive)
            except Exception as e:        # noqa: BLE001 - try the next tier on any provider error
                last_err = e
                continue
        if last_err is not None:
            raise last_err
        raise RuntimeError("no healthy client available in FallbackClient")
