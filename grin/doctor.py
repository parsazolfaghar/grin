"""The environment doctor — inspects Grin's runtime requirements and reports each as a
Check (ok/missing/broken/skipped) with an optional Fix. Outside the spine; never touches a
target. All probes are injectable so the whole engine is testable with fakes."""
import importlib
import os
from dataclasses import dataclass

from grin.platform_info import PlatformInfo
from grin.arsenal import DEFAULT_ARSENALS


@dataclass(frozen=True)
class Fix:
    label: str      # human description
    command: str    # the EXACT command shown to the user before anything runs
    kind: str       # "auto" (confirm + run) | "advisory" (print only, never auto-run)
    runner: str     # "host" | "ollama" | "pip" | "env"


@dataclass(frozen=True)
class Check:
    name: str
    status: str     # "ok" | "missing" | "broken" | "skipped"
    detail: str
    fix: "Fix | None" = None


@dataclass(frozen=True)
class DoctorReport:
    platform: PlatformInfo
    checks: list

    @property
    def ok(self) -> bool:
        return all(c.status in ("ok", "skipped") for c in self.checks)

    def fixable(self) -> list:
        return [c for c in self.checks if c.fix is not None and c.fix.kind == "auto"]


def _import_ok(mod: str) -> bool:
    try:
        importlib.import_module(mod)
        return True
    except ImportError:
        return False


def check_engine_deps(want_docker: bool) -> list:
    checks = []
    for mod, pip_name in (("yaml", "pyyaml"), ("httpx", "httpx")):
        ok = _import_ok(mod)
        checks.append(Check(
            name=f"engine dep: {pip_name}",
            status="ok" if ok else "broken",
            detail="importable" if ok else f"missing Python package {pip_name}",
            fix=None if ok else Fix(f"install {pip_name}", f"pip install {pip_name}", "auto", "pip"),
        ))
    if not want_docker:
        checks.append(Check("engine dep: docker", "skipped",
                            "not needed (no docker env in this engagement)"))
    else:
        ok = _import_ok("docker")
        checks.append(Check(
            name="engine dep: docker",
            status="ok" if ok else "broken",
            detail="docker SDK importable" if ok else "missing the docker Python SDK",
            fix=None if ok else Fix("install the docker extra", "pip install 'grin[docker]'",
                                    "auto", "pip"),
        ))
    return checks


def check_ollama(client) -> Check:
    url = getattr(client, "base_url", "local")
    if client.is_up():
        return Check("Ollama daemon", "ok", f"reachable at {url}")
    return Check("Ollama daemon", "broken", f"not reachable at {url} — start Ollama (or check the tunnel)",
                 fix=Fix("start Ollama", "ollama serve", "advisory", "host"))


def check_model_backend(client, backend: str) -> Check:
    """Backend-aware model check. ollama -> existing reachability check; openai -> key present +
    endpoint reachable."""
    if backend == "openai":
        if not os.environ.get("GRIN_MODEL_API_KEY"):
            return Check("model backend: openai", "broken", "GRIN_MODEL_API_KEY not set",
                         fix=Fix("set API key", "export GRIN_MODEL_API_KEY=...", "advisory", "env"))
        if not client.is_up():
            url = os.environ.get("GRIN_MODEL_URL", "(unset)")
            return Check("model backend: openai", "broken", f"endpoint not reachable at {url}",
                         fix=Fix("check GRIN_MODEL_URL / network", "", "advisory", "env"))
        return Check("model backend: openai", "ok",
                     f"reachable at {os.environ.get('GRIN_MODEL_URL', '')}")
    return check_ollama(client)


def check_models(client, required: list) -> list:
    if not client.is_up():
        return [Check(f"model {m}", "skipped", "Ollama down — cannot query models")
                for m in required]
    installed = set(client.installed_models())
    checks = []
    for m in required:
        present = m in installed
        checks.append(Check(
            name=f"model {m}",
            status="ok" if present else "missing",
            detail="pulled" if present else "not pulled",
            fix=None if present else Fix(f"pull model {m}", f"ollama pull {m}", "auto", "ollama"),
        ))
    return checks


def _docker_install_cmd(image_hint: str, tool: str) -> str:
    # BlackArch uses pacman; Kali/Debian use apt-get. Heuristic on the container name.
    if "blackarch" in image_hint.lower():
        return f"pacman -Sy --noconfirm {tool}"
    return f"apt-get update && apt-get install -y {tool}"


def check_env(engagement, *, ssh_prober, docker_prober) -> list:
    env = engagement.env or {}
    kind = env.get("kind", "local")
    if kind == "local":
        return [Check("env: local", "ok", "runs on this host — no external env needed")]
    if kind == "ssh":
        host = env.get("ssh_host", "?")
        reachable = ssh_prober(host) if ssh_prober else False
        if reachable:
            return [Check(f"env: ssh {host}", "ok", "reachable over key-based SSH")]
        return [Check(f"env: ssh {host}", "broken", "not reachable over SSH",
                      fix=Fix("set up SSH access",
                              f"ssh-copy-id {host}   # then verify: ssh {host} true",
                              "advisory", "host"))]
    if kind == "docker":
        cont = env.get("container", "?")
        probe = docker_prober(cont) if docker_prober else {"daemon": False, "container": False}
        checks = []
        if probe.get("daemon"):
            checks.append(Check("docker daemon", "ok", "reachable"))
        else:
            checks.append(Check("docker daemon", "broken", "docker daemon not reachable",
                                fix=Fix("start docker", "sudo systemctl start docker",
                                        "advisory", "host")))
        if probe.get("container"):
            checks.append(Check(f"docker container {cont}", "ok", "present"))
        else:
            checks.append(Check(f"docker container {cont}", "missing",
                                f"container {cont!r} not found",
                                fix=Fix(f"create {cont}",
                                        f"docker run -d --name {cont} --network host "
                                        f"<image> sleep infinity", "advisory", "host")))
        return checks
    return [Check(f"env: {kind}", "broken", f"unknown env kind {kind!r}")]


def check_arsenal(containers, *, running_probe) -> list:
    """For env.kind == 'arsenal': each arsenal container must be running.
    running_probe(name) -> bool is injected so this is pure + testable."""
    checks = []
    for c in containers:
        if running_probe(c):
            checks.append(Check(f"arsenal: {c}", "ok", "running"))
        else:
            checks.append(Check(f"arsenal: {c}", "broken", "not running",
                                fix=Fix("provision arsenal", "grin arsenal up",
                                        "advisory", "host")))
    return checks


def check_tools(engagement, runner, tools: list) -> list:
    env = engagement.env or {}
    image_hint = env.get("container", "")
    checks = []
    for t in tools:
        # The runner's `target` arg is ignored by every concrete runner (each runs on its own
        # bound arsenal host); we pass a scope host only to satisfy the signature.
        res = runner.run(engagement.scope.include[0] if engagement.scope.include else "localhost",
                         f"command -v {t}")
        present = res.exit_code == 0 and not res.timed_out
        if present:
            checks.append(Check(f"tool: {t}", "ok", "on PATH in the engagement env"))
        else:
            cmd = _docker_install_cmd(image_hint, t)
            checks.append(Check(f"tool: {t}", "missing", "not found in the engagement env",
                                fix=Fix(f"install {t} in the env", cmd, "auto", "env")))
    return checks


def run_doctor(*, platform, ollama, engagement, runner, required_models, tools,
               ssh_prober=None, docker_prober=None, backend: str = "ollama") -> DoctorReport:
    checks = [Check("OS", "ok", f"{platform.os} (pkg mgr: {platform.host_pkg_mgr})")]
    want_docker = bool(engagement and (engagement.env or {}).get("kind") == "docker")
    checks += check_engine_deps(want_docker)
    backend_check = check_model_backend(ollama, backend)
    checks.append(backend_check)
    if backend == "openai":
        # Hosted API — model presence is managed by the provider; skip local pull checks.
        checks += [Check(f"model {m}", "skipped", "cloud backend — model availability managed by provider")
                   for m in required_models]
    else:
        checks += check_models(ollama, required_models)
    if engagement is not None:
        env_kind = (engagement.env or {}).get("kind")
        if env_kind == "arsenal":
            containers = (engagement.env or {}).get("containers") or DEFAULT_ARSENALS
            if docker_prober:
                def running_probe(c):
                    return bool((docker_prober(c) or {}).get("container", False))
            else:
                def running_probe(c):
                    return False
            arsenal_checks = check_arsenal(containers, running_probe=running_probe)
            checks += arsenal_checks
            env_ok = all(c.status in ("ok", "skipped") for c in arsenal_checks)
        else:
            env_checks = check_env(engagement, ssh_prober=ssh_prober, docker_prober=docker_prober)
            checks += env_checks
            env_ok = all(c.status in ("ok", "skipped") for c in env_checks)
        if env_ok and runner is not None:
            checks += check_tools(engagement, runner, tools)
        else:
            checks += [Check(f"tool: {t}", "skipped", "env unreachable — skipped tool probe")
                       for t in tools]
    return DoctorReport(platform=platform, checks=checks)
