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

# The deterministic helpers/closers (grin/tools/<src>.py) deployed into the arsenal containers as
# /usr/local/bin/<name>. They run INSIDE the containers, so an update must re-deploy them here — a
# `git pull` alone leaves the containers on the old helper. Single source of truth (provision-runner
# mirrors this list).
HELPERS = {
    "webexec": "web-rce", "sshloot": "ssh-loot", "suidhijack": "suid-hijack",
    "webscan": "web-scan", "idrive": "grin-shell", "sudoesc": "sudo-gtfo",
    "credsweep": "cred-sweep", "lficrack": "lfi-crack",
    "adbtakeover": "adb-takeover", "bac_probe": "bac-probe", "idor_probe": "idor-probe",
}

# The two arsenals are COMPLEMENTARY, not redundant: tools are split so a real engagement must reach
# BOTH. Kali carries recon + web exploitation + the deterministic helpers; BlackArch owns the
# brute-force / online-cracking tools (hydra, medusa). Because ArsenalRunner prefers Kali first, a
# tool present ONLY on BlackArch (hydra) deterministically routes there — so e.g. an SSH-brute step
# exercises BlackArch every run. This is what makes "grin uses both" verifiable, not incidental.
BASELINE = {
    "apt": ["nmap", "sqlmap", "nikto", "gobuster", "ffuf", "netcat-traditional",
            "openssh-client", "sshpass", "curl", "wget", "iputils-ping", "wordlists", "john"],
    # pacman/BlackArch package names differ: netcat is openbsd-netcat (gnu-netcat isn't in the synced
    # repos); there is no 'wordlists' meta-package (run_up writes its own curated lists anyway).
    # hydra/medusa (brute) + the ProjectDiscovery suite (nuclei/httpx/subfinder) live HERE ONLY, so
    # brute-force AND broad CVE/misconfig scanning route to BlackArch — real-world coverage + every
    # web engagement exercises BlackArch.
    "pacman": ["hydra", "medusa", "nuclei", "httpx", "subfinder",
               "nmap", "sqlmap", "nikto", "gobuster", "ffuf", "openbsd-netcat",
               "openssh", "sshpass", "curl", "wget", "iputils", "john"],
}

# Tools intentionally kept OFF the Kali arsenal so they route to BlackArch (verifies cross-arsenal use
# and gives grin ProjectDiscovery-grade real-world coverage).
BLACKARCH_ONLY = ("hydra", "medusa", "nuclei", "httpx", "subfinder")


def distro_for(container: str) -> str:
    return _DISTRO.get(container, "apt")


def run_container_argv(name: str, image: str) -> list:
    return ["docker", "run", "-d", "--name", name, "--network", "host", image, "sleep", "infinity"]


def install_cmd(distro: str, tools: list, tolerant: bool = False) -> str:
    """Build the in-container install command. tolerant=True installs each package separately and
    swallows per-package failures (`|| true`) so ONE bad/renamed package name doesn't abort the whole
    batch — critical for pacman, which fails the entire transaction on a single unknown target. Used
    for the baseline sweep. Non-tolerant (default) keeps the single-shot form add_cmd relies on for a
    real exit code."""
    pkgs = list(tools)
    if distro == "pacman":
        if tolerant:
            inner = "; ".join(f"pacman -S --noconfirm --needed {p} || true" for p in pkgs)
            return f"pacman -Sy --noconfirm; {inner}"
        return f"pacman -Sy --noconfirm {' '.join(pkgs)}"
    if tolerant:
        inner = "; ".join(
            f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {p} || true" for p in pkgs)
        return f"apt-get update -qq; {inner}"
    return f"apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {' '.join(pkgs)}"


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
        # tolerant: a single renamed/missing package must not abort the whole baseline (pacman aborts
        # the entire transaction otherwise). Per-package failures are surfaced by `arsenal status`.
        ic = _run(["docker", "exec", name, "sh", "-lc",
                   install_cmd(distro, BASELINE[distro], tolerant=True)])
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


def run_deploy_helpers() -> int:
    """Deploy grin/tools/<src>.py into each running arsenal container as /usr/local/bin/<name>, so an
    update's helper/closer fixes actually reach the containers (where they run). Idempotent."""
    import os
    tools_dir = os.path.join(os.path.dirname(__file__), "tools")
    n = 0
    for name in ARSENAL_IMAGES:
        if not _exists(name):
            continue
        for src, dst in HELPERS.items():
            sp = os.path.join(tools_dir, f"{src}.py")
            if not os.path.exists(sp):
                continue
            if _run(["docker", "cp", sp, f"{name}:/usr/local/bin/{dst}"]).returncode == 0:
                _run(["docker", "exec", name, "sh", "-lc",
                      f"sed -i '1s|.*|#!/usr/bin/env python3|' /usr/local/bin/{dst} "
                      f"&& chmod +x /usr/local/bin/{dst}"])
                n += 1
    print(f"deployed {n} helper instance(s) across arsenal containers")
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
