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
