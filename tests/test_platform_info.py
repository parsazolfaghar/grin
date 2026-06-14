from grin.platform_info import detect_platform, PlatformInfo

def test_macos_maps_to_brew():
    p = detect_platform(system=lambda: "Darwin", which=lambda c: "/x" if c == "brew" else None)
    assert (p.os, p.host_pkg_mgr) == ("macos", "brew")
    assert p.raw == "Darwin"

def test_linux_maps_to_apt():
    p = detect_platform(system=lambda: "Linux", which=lambda c: "/x" if c == "apt-get" else None)
    assert (p.os, p.host_pkg_mgr) == ("linux", "apt")

def test_windows_maps_to_winget():
    p = detect_platform(system=lambda: "Windows", which=lambda c: "/x" if c == "winget" else None)
    assert (p.os, p.host_pkg_mgr) == ("windows", "winget")

def test_unknown_os_and_missing_pkg_mgr():
    p = detect_platform(system=lambda: "Plan9", which=lambda c: None)
    assert p.os == "unknown"
    assert p.host_pkg_mgr == "unknown"

def test_linux_without_apt_is_unknown_mgr():
    p = detect_platform(system=lambda: "Linux", which=lambda c: None)
    assert (p.os, p.host_pkg_mgr) == ("linux", "unknown")
