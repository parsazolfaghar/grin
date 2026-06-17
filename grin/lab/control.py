"""Control the flag-lab: build/up/down/reset/status + reachability check from the runner.
argv builders are pure (tested); run_* wrappers shell out (validated live on the rig)."""
import subprocess
from pathlib import Path

from grin.lab.answers import load_answers

LAB_CONTAINERS = ["grin-lab-ssh", "grin-lab-web", "grin-lab-chain", "grin-lab-crack",
                  "grin-lab-suid", "grin-lab-pivot-web", "grin-lab-pivot-vault"]
LAB_DIR = Path(__file__).resolve().parents[2] / "lab"


def compose_argv(action: str, compose_file: str) -> list:
    base = ["docker", "compose", "-f", compose_file]
    if action == "up":
        return base + ["up", "-d"]
    if action == "build":
        return base + ["build"]
    if action == "down":
        return base + ["down"]
    raise ValueError(f"unknown compose action {action!r}")


def reset_argv() -> list:
    return ["docker", "restart", *LAB_CONTAINERS]


def reachable_argv(runner_container: str, ip: str, port: int) -> list:
    return ["docker", "exec", runner_container, "nmap", "-Pn", f"-p{port}", ip]


def _run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, **kw)


def run_up(compose_file=None) -> int:
    """Generate flags+answers, build, and start the lab. Returns process return code."""
    import sys
    cf = compose_file or str(LAB_DIR / "docker-compose.yml")
    build = _run([sys.executable, str(LAB_DIR / "build.py"), "--keep"])
    print(build.stdout or build.stderr, end="")
    for action in ("build", "up"):
        r = _run(compose_argv(action, cf))
        print(r.stdout or "", end="")
        if r.returncode != 0:
            print(r.stderr, end="")
            return r.returncode
    print("lab up. targets:")
    for t in load_answers(str(LAB_DIR / "answers.yaml")):
        print(f"  {t.id:10s} {t.ip:14s} ports={t.open_ports} ({t.tier})")
    return 0


def run_down(compose_file=None) -> int:
    cf = compose_file or str(LAB_DIR / "docker-compose.yml")
    r = _run(compose_argv("down", cf))
    print(r.stdout or r.stderr, end="")
    return r.returncode


def run_reset() -> int:
    r = _run(reset_argv())
    print(r.stdout or r.stderr, end="")
    return r.returncode


def run_status(runner_container="grin-kali") -> int:
    targets = load_answers(str(LAB_DIR / "answers.yaml"))
    for t in targets:
        ps = _run(["docker", "inspect", "-f", "{{.State.Running}}", t.container])
        up = ps.stdout.strip() == "true"
        reach = "?"
        if up:
            rr = _run(reachable_argv(runner_container, t.ip, t.open_ports[0]))
            reach = "open" if "open" in (rr.stdout or "") else "unreachable"
        print(f"  {t.id:10s} {t.ip:14s} running={up} runner-reach={reach}")
    return 0
