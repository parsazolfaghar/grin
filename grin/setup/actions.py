"""Pure, injectable setup actions for the Grin setup wizard. All side effects go through injected
`run` (argv -> result with .returncode/.stdout) and `which` (shutil.which-like) so every branch is
unit-testable without touching the real system. OS-aware via an explicit `os_name`."""
import os


def write_env(path: str, *, api_key: str, url: str, backend: str = "openai") -> None:
    """Write the GRIN_MODEL_* config to `path` (0600 on POSIX)."""
    path = os.path.expanduser(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    body = (f"GRIN_MODEL_BACKEND={backend}\n"
            f"GRIN_MODEL_URL={url}\n"
            f"GRIN_MODEL_API_KEY={api_key}\n")
    with open(path, "w") as fh:
        fh.write(body)
    if os.name == "posix":
        os.chmod(path, 0o600)


def docker_status(run, which) -> dict:
    """{'installed': docker on PATH, 'running': `docker info` exits 0}."""
    if not which("docker"):
        return {"installed": False, "running": False}
    r = run(["docker", "info"])
    return {"installed": True, "running": r.returncode == 0}
