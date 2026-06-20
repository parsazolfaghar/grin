"""Execution layer — runs a command INSIDE the engagement's bound Kali/BlackArch
environment and captures output + exit code + duration. Adapted from the Sensei
sandbox.py runners; the env is operator-provided (Grin drives it, never provisions
it). Every run has a hard timeout."""
import os
import shlex
import subprocess
import time
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ExecResult:
    output: str            # combined stdout+stderr
    exit_code: int | None  # None when timed out / unknown
    duration_s: float
    timed_out: bool


class Runner(Protocol):
    def run(self, target: str, command: str, timeout: int = 60) -> ExecResult: ...


class FakeRunner:
    """Deterministic stand-in for tests / the Mac (no real tooling)."""

    def __init__(self, outputs: dict[str, ExecResult] | None = None):
        self._outputs = outputs or {}

    def run(self, target: str, command: str, timeout: int = 60) -> ExecResult:
        if command in self._outputs:
            return self._outputs[command]
        return ExecResult(output=f"[fake output for: {command}]", exit_code=0,
                          duration_s=0.0, timed_out=False)


class LocalRunner:
    """Runs on THIS host's shell (the operator's own machine / a local lab)."""

    def __init__(self, default_timeout: int = 60):
        self._default_timeout = default_timeout

    def run(self, target: str, command: str, timeout: int | None = None) -> ExecResult:
        timeout = timeout or self._default_timeout
        start = time.monotonic()
        try:
            p = subprocess.run(["bash", "-lc", command], capture_output=True, text=True,
                               timeout=timeout)
        except subprocess.TimeoutExpired:
            return ExecResult(output=f"[timed out after {timeout}s]", exit_code=None,
                              duration_s=time.monotonic() - start, timed_out=True)
        return ExecResult(output=(p.stdout + p.stderr).strip(), exit_code=p.returncode,
                          duration_s=time.monotonic() - start, timed_out=False)


class SSHRunner:
    """Runs on a Kali/BlackArch box over key-based SSH (the attacker vantage)."""

    def __init__(self, ssh_host: str, default_timeout: int = 60):
        self._host = ssh_host
        self._default_timeout = default_timeout

    def run(self, target: str, command: str, timeout: int | None = None) -> ExecResult:
        timeout = timeout or self._default_timeout
        remote = f"timeout {int(timeout)} bash -lc {shlex.quote(command)}"
        start = time.monotonic()
        try:
            p = subprocess.run(
                ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", self._host, remote],
                capture_output=True, text=True, timeout=timeout + 15)
        except subprocess.TimeoutExpired:
            return ExecResult(output=f"[ssh timed out after {timeout}s]", exit_code=None,
                              duration_s=time.monotonic() - start, timed_out=True)
        return ExecResult(output=(p.stdout + p.stderr).strip(), exit_code=p.returncode,
                          duration_s=time.monotonic() - start, timed_out=False)


class DockerRunner:
    """Runs inside a Kali/BlackArch container. Live only ([docker] extra)."""

    def __init__(self, container: str, default_timeout: int = 60):
        import docker  # requires the [docker] extra
        self._client = docker.from_env()
        self._container = container
        self._default_timeout = default_timeout

    def run(self, target: str, command: str, timeout: int | None = None) -> ExecResult:
        timeout = timeout or self._default_timeout
        container = self._client.containers.get(self._container)
        wrapped = ["sh", "-c", f"timeout {int(timeout)} sh -c {shlex.quote(command)}"]
        start = time.monotonic()
        exit_code, output = container.exec_run(wrapped, demux=False)
        if isinstance(output, (bytes, bytearray)):
            output = output.decode("utf-8", "replace")
        return ExecResult(output="" if output is None else str(output),
                          exit_code=exit_code, duration_s=time.monotonic() - start,
                          timed_out=False)


from grin.arsenal import DEFAULT_ARSENALS, resolve_tool, distro_for, add_cmd

_AUTO_CLIENT = object()  # sentinel: client not supplied -> auto-detect (vs an explicit None = no client)


class ArsenalRunner:
    """Runs each command in whichever provisioned arsenal container has the tool (prefer order).
    tool->container resolution cached per run. Missing tool -> clear error unless
    GRIN_ARSENAL_AUTOINSTALL=1 (install then retry). Live only ([docker] extra)."""

    def __init__(self, containers=DEFAULT_ARSENALS, default_timeout: int = 60, client=_AUTO_CLIENT,
                 autoinstall: bool | None = None, acquire: str | None = None, requests=None):
        # client omitted -> auto-detect from the docker SDK; an EXPLICIT None means "no client"
        # (used by tests + callers without a daemon) and must stay None even when the SDK is present.
        if client is _AUTO_CLIENT:
            try:
                import docker
                client = docker.from_env()
            except Exception:  # noqa: BLE001 - construction must not fail without a daemon
                client = None
        self._client = client
        self._containers = list(containers)
        self._timeout = default_timeout
        self._cache: dict[str, str] = {}
        self._requests = requests
        if acquire in ("auto", "ask", "never"):
            self._acquire = acquire
        elif autoinstall is True or os.environ.get("GRIN_ARSENAL_AUTOINSTALL") == "1":
            self._acquire = "auto"
        else:
            self._acquire = "ask"
        self._autoinstall = self._acquire == "auto"   # back-compat for any reader

    def _probe(self, container: str, tool: str) -> bool:
        if self._client is None:
            return False
        try:
            code, _ = self._client.containers.get(container).exec_run(
                ["sh", "-lc", f"command -v {tool}"], demux=False)
            return code == 0
        except Exception:  # noqa: BLE001
            return False

    def _resolve(self, tool: str):
        if tool in self._cache:
            return self._cache[tool]
        c = resolve_tool(tool, self._containers, self._probe)
        if c:
            self._cache[tool] = c
        return c

    def _install(self, tool: str):
        if self._client is None:
            return None
        for c in self._containers:
            try:
                code, _ = self._client.containers.get(c).exec_run(
                    ["sh", "-lc", add_cmd(distro_for(c), tool)], demux=False)
                if code == 0 and self._probe(c, tool):
                    self._cache[tool] = c
                    return c
            except Exception:  # noqa: BLE001
                continue
        return None

    def run(self, target: str, command: str, timeout: int | None = None) -> ExecResult:
        parts = command.split()
        tool = parts[0] if parts else ""
        container = self._resolve(tool)
        if container is None:
            if self._acquire == "auto":
                container = self._install(tool)
            elif self._acquire == "ask" and self._requests is not None:
                self._requests.request(tool)
                return ExecResult(
                    output=f"tool '{tool}' not in arsenal — awaiting approval in the app",
                    exit_code=127, duration_s=0.0, timed_out=False)
        if container is None:
            return ExecResult(output=f"tool '{tool}' not in arsenal — run `grin arsenal add {tool}`",
                              exit_code=127, duration_s=0.0, timed_out=False)
        # routing visibility: when GRIN_ARSENAL_LOG is set, record which arsenal container served each
        # tool, so a run can be shown to genuinely reach BOTH grin-kali and grin-blackarch.
        _log = os.environ.get("GRIN_ARSENAL_LOG")
        if _log:
            try:
                with open(_log, "a") as _fh:
                    _fh.write(f"{container}\t{tool}\n")
            except OSError:
                pass
        t0 = time.monotonic()
        wrapped = ["sh", "-lc", f"timeout {timeout or self._timeout} {command}"]
        code, out = self._client.containers.get(container).exec_run(wrapped, demux=False)
        output = out.decode("utf-8", "replace") if isinstance(out, (bytes, bytearray)) else str(out or "")
        return ExecResult(output=output, exit_code=code if code is not None else -1,
                          duration_s=round(time.monotonic() - t0, 3), timed_out=False)


def _arsenal_from_env(env: dict, timeout: int) -> "ArsenalRunner":
    """Build an ArsenalRunner, threading tool-acquire policy + request store from env."""
    from grin.toolrequest import ToolRequestStore
    acquire = env.get("tool_acquire")
    req_path = env.get("tool_requests")
    requests = ToolRequestStore(req_path) if req_path else None
    return ArsenalRunner(env.get("containers") or DEFAULT_ARSENALS, default_timeout=timeout,
                         acquire=acquire, requests=requests)


def build_runner(env: dict) -> Runner:
    """Build the runner for an engagement's bound environment."""
    kind = (env or {}).get("kind", "local")
    timeout = int((env or {}).get("timeout", 60))
    if kind == "local":
        return LocalRunner(default_timeout=timeout)
    if kind == "ssh":
        return SSHRunner(env["ssh_host"], default_timeout=timeout)
    if kind == "docker":
        return DockerRunner(env["container"], default_timeout=timeout)
    if kind == "arsenal":
        return _arsenal_from_env(env, timeout)
    if kind == "auto":
        from grin.platform_info import host_has_arsenal
        if host_has_arsenal():
            return LocalRunner(default_timeout=timeout)
        return _arsenal_from_env(env, timeout)
    raise ValueError(f"unknown env kind: {kind!r}")
