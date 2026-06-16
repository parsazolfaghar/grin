"""Host environment awareness — what OS are we on and which package manager can install
host tools. Pure + injectable so the doctor is testable on any platform."""
import platform
import shutil
from dataclasses import dataclass

_OS_MAP = {"Darwin": "macos", "Linux": "linux", "Windows": "windows"}
# preferred host package manager per OS, with the command that proves it's present
_PKG_MGR = {"macos": ("brew", "brew"), "linux": ("apt", "apt-get"), "windows": ("winget", "winget")}


@dataclass(frozen=True)
class PlatformInfo:
    os: str            # "macos" | "linux" | "windows" | "unknown"
    raw: str           # platform.system() raw value
    host_pkg_mgr: str  # "brew" | "apt" | "winget" | "unknown"


def detect_platform(system=platform.system, which=shutil.which) -> PlatformInfo:
    raw = system()
    os_name = _OS_MAP.get(raw, "unknown")
    mgr = "unknown"
    if os_name in _PKG_MGR:
        name, probe = _PKG_MGR[os_name]
        if which(probe):
            mgr = name
    return PlatformInfo(os=os_name, raw=raw, host_pkg_mgr=mgr)


_PENTEST_IDS = ("kali", "parrot", "blackarch")
# nmap plus at least one of these = a real arsenal (not just a box that happens to have nmap)
_QUORUM_TOOLS = ("hydra", "sqlmap", "nikto", "gobuster", "ffuf")


def _os_release_is_pentest(os_release_path: str) -> bool:
    try:
        with open(os_release_path) as fh:
            text = fh.read().lower()
    except OSError:
        return False
    for line in text.splitlines():
        if line.startswith("id=") or line.startswith("id_like="):
            val = line.split("=", 1)[1].strip().strip('"').strip("'")
            if any(pid in val.split() or pid == val for pid in _PENTEST_IDS):
                return True
    return False


def host_has_arsenal(which=shutil.which, os_release_path: str = "/etc/os-release") -> bool:
    """True when this host can run the offensive arsenal locally: a Kali/Parrot/BlackArch distro, or
    nmap plus at least one heavier offensive tool on PATH. Never raises — used to resolve env.kind
    'auto' to LocalRunner vs the Docker ArsenalRunner."""
    if _os_release_is_pentest(os_release_path):
        return True
    if which("nmap") and any(which(t) for t in _QUORUM_TOOLS):
        return True
    return False
