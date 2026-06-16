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


_DOCKER_URL = "https://www.docker.com/products/docker-desktop/"


def docker_install_plan(os_name: str, which) -> dict:
    """Decide how to install Docker per OS (pure, no execution). mode 'auto' -> run command (the OS
    shows its own admin/sudo prompt); 'guide' -> the wizard shows note/URL for a manual step."""
    if os_name == "macos":
        if which("brew"):
            return {"mode": "auto", "command": ["brew", "install", "--cask", "docker"],
                    "note": "Installing Docker Desktop via Homebrew (you may be prompted)."}
        return {"mode": "guide", "command": [],
                "note": f"Install Docker Desktop for Mac: {_DOCKER_URL}"}
    if os_name == "windows":
        if which("winget"):
            return {"mode": "auto",
                    "command": ["winget", "install", "-e", "--id", "Docker.DockerDesktop"],
                    "note": "Installing Docker Desktop via winget (accept the UAC prompt; "
                            "Windows may need a reboot to finish WSL2 setup)."}
        return {"mode": "guide", "command": [],
                "note": f"Install Docker Desktop for Windows: {_DOCKER_URL}"}
    if os_name == "linux":
        if which("curl"):
            return {"mode": "auto", "command": ["sh", "-c", "curl -fsSL https://get.docker.com | sudo sh"],
                    "note": "Installing Docker Engine via the official script (you'll be asked for sudo). "
                            "You may need to log out/in for the docker group to apply."}
        return {"mode": "guide", "command": [],
                "note": f"Install Docker for your distro: {_DOCKER_URL}"}
    return {"mode": "guide", "command": [], "note": f"Install Docker: {_DOCKER_URL}"}


def run_install_plan(plan: dict, run) -> dict:
    """Execute an 'auto' plan; pass a 'guide' plan straight back for the wizard to display."""
    if plan.get("mode") != "auto":
        return {"status": "guide", "note": plan.get("note", "")}
    r = run(plan["command"])
    return {"status": "installed" if r.returncode == 0 else "failed", "note": plan.get("note", "")}


def install_grin(os_name: str, *, src: str, dest: str) -> dict:
    """Place the bundled Grin into `dest` (e.g. /Applications). Clean-replaces an existing copy.
    macOS: a .app is itself the launcher. (Linux .desktop / Windows shortcut: Phase 2.)"""
    import shutil
    if not src or not src.strip("/"):
        raise ValueError("install_grin: empty src (no Grin payload to install)")
    name = os.path.basename(src.rstrip("/"))
    target = os.path.join(dest, name)
    if not name:   # defensive: never let target collapse to `dest` itself (would rmtree it)
        raise ValueError(f"install_grin: cannot derive a bundle name from src {src!r}")
    if os.path.isdir(target):
        shutil.rmtree(target)
    elif os.path.exists(target):
        os.remove(target)
    os.makedirs(dest, exist_ok=True)
    if os.path.isdir(src):
        shutil.copytree(src, target)
    else:
        shutil.copy2(src, target)
    return {"installed_to": target}


def provision_arsenal(run) -> dict:
    """Pull the Kali/BlackArch arsenal containers (`grin arsenal up`)."""
    r = run(["grin", "arsenal", "up"])
    return {"status": "ok" if r.returncode == 0 else "failed"}
