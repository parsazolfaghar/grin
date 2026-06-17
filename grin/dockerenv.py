"""Resolve DOCKER_HOST for an environment that doesn't have it set. A clicked Grin.app (and any
shell that hasn't exported it) starts with a bare environment: the docker SDK's from_env() only
checks $DOCKER_HOST then the default /var/run/docker.sock — but Colima (and Docker Desktop) put the
daemon socket elsewhere, so DockerRunner can't connect. Probe the common socket locations and point
DOCKER_HOST at the first that exists. An explicit DOCKER_HOST is always respected."""
import os


def resolve_docker_host(environ, exists=os.path.exists) -> str | None:
    """Return a `unix://…` DOCKER_HOST for the first daemon socket that exists, or None if one is
    already set / none is found. Pure: environ + exists are injected so it's unit-testable."""
    if environ.get("DOCKER_HOST"):
        return None
    home = environ.get("HOME") or os.path.expanduser("~")
    candidates = (
        f"{home}/.colima/default/docker.sock",   # Colima (current layout)
        f"{home}/.colima/docker.sock",           # Colima (legacy)
        "/var/run/docker.sock",                  # standard daemon / Docker Desktop symlink
        f"{home}/.docker/run/docker.sock",       # Docker Desktop (macOS)
    )
    for path in candidates:
        if exists(path):
            return f"unix://{path}"
    return None


def ensure_docker_host(environ=None) -> str | None:
    """Set DOCKER_HOST in the environment if it's unset and a known socket exists. Returns the value
    set, or None if nothing changed. Call early (app/CLI startup), before any DockerRunner is built."""
    environ = environ if environ is not None else os.environ
    host = resolve_docker_host(environ)
    if host:
        environ["DOCKER_HOST"] = host
    return host
