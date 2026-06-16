"""Optional dotenv loader so a launcher/Finder-clicked app (which has no shell env) can still pick
up GRIN_MODEL_* (and other) config from ~/.grin/env. Never overrides a var already set in the real
environment; never raises on a missing/garbled file."""
import os

DEFAULT_ENV_PATH = os.path.expanduser("~/.grin/env")


def load_env_file(path: str = DEFAULT_ENV_PATH) -> dict:
    path = os.path.expanduser(path)
    applied: dict = {}
    try:
        with open(path) as fh:
            lines = fh.readlines()
    except OSError:
        return applied
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if not key:
            continue
        if key in os.environ:
            continue
        os.environ[key] = val
        applied[key] = val
    return applied
