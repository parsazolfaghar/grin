"""App deployment profiles (roadmap R4): the user toggles where Grin runs.

A profile bundles { model_backend, ollama_url, env } — flipping the active profile rewires the
brain AND the tool-execution environment at once, and is AUTHORITATIVE over the brain (it pins
$GRIN_MODEL_BACKEND so cloud creds in ~/.grin/env can't silently override a local/split choice):
  - cloud: DeepSeek (or any GRIN_MODEL_* cloud) brain + self-provisioned Docker arsenal. The
    device-independent default — a laptop with Docker is full Grin, no rig.
  - local: local Ollama brain + local tools, everything on this machine.
  - split: app here, GPU Ollama inference + Kali/BlackArch arsenal on the rig over SSH.

Applying a profile sets $GRIN_MODEL_BACKEND (ollama|openai), $GRIN_OLLAMA_URL (so the engine's
OllamaClient points at the chosen endpoint), and exposes the profile's `env` for app-launched
engagements. Cloud creds (URL/KEY) are NOT stored here — they come from ~/.grin/env. Persisted as
JSON; the config path is injectable for tests. Charter unchanged — the spine authorizes every action.
"""
import json
import os

DEFAULT_PROFILES = {
    "cloud": {
        "label": "CLOUD",
        "model_backend": "openai",        # uses GRIN_MODEL_URL/KEY from ~/.grin/env (no secrets here)
        "ollama_url": "http://127.0.0.1:11434",   # ignored while the cloud backend is active
        "env": {"kind": "arsenal"},       # tools run in self-provisioned local Docker (Kali/BlackArch)
    },
    "local": {
        "label": "LOCAL",
        "model_backend": "ollama",
        "ollama_url": "http://127.0.0.1:11434",
        "env": {"kind": "local"},
    },
    "split": {
        "label": "SPLIT (RIG)",
        "model_backend": "ollama",
        # default points directly at the rig; for security prefer an SSH tunnel
        # (`ssh -L 11434:localhost:11434 root@rig`) and set this to http://127.0.0.1:11434.
        "ollama_url": "http://your-rig:11434",
        "env": {"kind": "ssh", "ssh_host": "root@your-rig"},
    },
}
ORDER = ["cloud", "local", "split"]


def config_path() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "grin", "app.json")


def load(path: str | None = None) -> dict:
    path = path or config_path()
    data = {"active": "cloud", "profiles": json.loads(json.dumps(DEFAULT_PROFILES))}
    try:
        with open(path) as f:
            saved = json.load(f)
        if isinstance(saved, dict):
            data["active"] = saved.get("active", data["active"])
            for name, prof in (saved.get("profiles") or {}).items():
                data["profiles"][name] = prof
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    if data["active"] not in data["profiles"]:
        data["active"] = "cloud"
    return data


def save(data: dict, path: str | None = None) -> None:
    path = path or config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def get_active(path: str | None = None):
    data = load(path)
    name = data["active"]
    return name, data["profiles"][name]


def set_active(name: str, path: str | None = None) -> dict:
    data = load(path)
    if name not in data["profiles"]:
        raise ValueError(f"unknown profile {name!r}")
    data["active"] = name
    save(data, path)
    return data["profiles"][name]


def next_profile(name: str) -> str:
    """Cycle to the next profile name (for a simple toggle button)."""
    if name not in ORDER:
        return ORDER[0]
    return ORDER[(ORDER.index(name) + 1) % len(ORDER)]


def apply_profile(profile: dict) -> dict:
    """Pin this profile's brain backend + Ollama endpoint, then return its tool env. Setting
    $GRIN_MODEL_BACKEND makes the deployment toggle authoritative over the brain — otherwise cloud
    creds in ~/.grin/env would win via active_backend() regardless of the chosen mode. Cloud
    URL/KEY still come from the environment (~/.grin/env); they are never stored in a profile."""
    backend = profile.get("model_backend")
    if backend:
        os.environ["GRIN_MODEL_BACKEND"] = backend
    os.environ["GRIN_OLLAMA_URL"] = profile["ollama_url"]
    return profile.get("env", {"kind": "local"})


def apply_active(path: str | None = None) -> dict:
    _name, profile = get_active(path)
    return apply_profile(profile)
