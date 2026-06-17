"""Self-provisioning multi-arsenal: stand up Kali + BlackArch containers on the local Docker and
install a curated offensive toolset into each. Pure command/argv builders + tool->container
resolution (unit-tested); run_* wrappers shell out to docker (validated live). Host-OS-agnostic —
provisioning runs inside the containers (apt/pacman)."""
import subprocess
import sys

DEFAULT_ARSENALS = ("grin-kali", "grin-blackarch")
ARSENAL_IMAGES = {
    "grin-kali": "kalilinux/kali-rolling",
    "grin-blackarch": "blackarchlinux/blackarch",
}
_DISTRO = {"grin-kali": "apt", "grin-blackarch": "pacman"}

BASELINE = {
    "apt": ["nmap", "hydra", "sqlmap", "nikto", "gobuster", "ffuf", "netcat-traditional",
            "openssh-client", "sshpass", "curl", "wget", "iputils-ping", "wordlists", "john"],
    "pacman": ["nmap", "hydra", "sqlmap", "nikto", "gobuster", "ffuf", "gnu-netcat",
               "openssh", "sshpass", "curl", "wget", "iputils", "wordlists", "john"],
}


def distro_for(container: str) -> str:
    return _DISTRO.get(container, "apt")


def run_container_argv(name: str, image: str) -> list:
    return ["docker", "run", "-d", "--name", name, "--network", "host", image, "sleep", "infinity"]


def install_cmd(distro: str, tools: list) -> str:
    pkgs = " ".join(tools)
    if distro == "pacman":
        return f"pacman -Sy --noconfirm {pkgs}"
    return f"apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {pkgs}"


def add_cmd(distro: str, tool: str) -> str:
    return install_cmd(distro, [tool])


def probe_argv(container: str, tool: str) -> list:
    return ["docker", "exec", container, "sh", "-lc", f"command -v {tool}"]


def resolve_tool(tool: str, containers, exec_probe) -> str | None:
    """First container (in order) whose exec_probe(container, tool) is True, else None.
    exec_probe is injected so this is pure + unit-testable."""
    for c in containers:
        if exec_probe(c, tool):
            return c
    return None


# ---- live wrappers (not unit-tested; validated on a Docker host) ----
def _run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, **kw)


def _exists(name: str) -> bool:
    return _run(["docker", "inspect", "-f", "{{.State.Status}}", name]).returncode == 0


def run_up() -> int:
    for name, image in ARSENAL_IMAGES.items():
        if not _exists(name):
            r = _run(run_container_argv(name, image))
            print(r.stdout or r.stderr, end="")
            if r.returncode != 0:
                return r.returncode
        else:
            _run(["docker", "start", name])
        distro = distro_for(name)
        print(f"provisioning {name} ({distro}) ...")
        ic = _run(["docker", "exec", name, "sh", "-lc", install_cmd(distro, BASELINE[distro])])
        if ic.returncode != 0:
            print(ic.stderr[-400:], end="")
            return ic.returncode
        _run(["docker", "exec", name, "sh", "-lc",
              "printf 'root\\nadmin\\nuser\\noperator\\nubuntu\\npi\\nguest\\ntest\\n' "
              "> /usr/share/wordlists/users.txt; "
              "printf 'password\\n123456\\nadmin\\npassword123\\nletmein\\nchangeme\\n' "
              "> /usr/share/wordlists/passwords.txt; "
              "printf 'Host *\\n  StrictHostKeyChecking no\\n  UserKnownHostsFile /dev/null\\n  "
              "LogLevel ERROR\\n' >> /etc/ssh/ssh_config 2>/dev/null || true"])
    print("arsenal up:", ", ".join(ARSENAL_IMAGES))
    return 0


def run_down() -> int:
    for name in ARSENAL_IMAGES:
        _run(["docker", "rm", "-f", name])
    print("arsenal down")
    return 0


def run_status() -> int:
    for name in ARSENAL_IMAGES:
        st = _run(["docker", "inspect", "-f", "{{.State.Running}}", name]).stdout.strip()
        up = st == "true"
        ntools = "0"
        if up:
            distro = distro_for(name)
            present = _run(["docker", "exec", name, "sh", "-lc",
                            "for t in " + " ".join(BASELINE[distro]) +
                            "; do command -v $t >/dev/null && echo $t; done | wc -l"])
            ntools = (present.stdout or "0").strip()
        print(f"  {name:16s} running={up} baseline_tools={ntools}")
    return 0


def run_add(tool: str) -> int:
    for name in ARSENAL_IMAGES:
        if not _exists(name):
            continue
        distro = distro_for(name)
        r = _run(["docker", "exec", name, "sh", "-lc", add_cmd(distro, tool)])
        if r.returncode == 0:
            print(f"installed {tool} into {name}")
            return 0
    print(f"could not install {tool} into any arsenal", file=sys.stderr)
    return 1
