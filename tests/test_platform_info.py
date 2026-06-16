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


from grin.platform_info import host_has_arsenal


def _wh(present):
    return lambda tool: ("/usr/bin/" + tool) if tool in present else None


def test_kali_os_release_is_arsenal(tmp_path):
    f = tmp_path / "os-release"
    f.write_text('ID=kali\nID_LIKE=debian\n')
    assert host_has_arsenal(which=_wh(set()), os_release_path=str(f)) is True


def test_parrot_and_blackarch_ids(tmp_path):
    p = tmp_path / "p"; p.write_text('ID=parrot\n')
    b = tmp_path / "b"; b.write_text('ID=blackarch\n')
    assert host_has_arsenal(which=_wh(set()), os_release_path=str(p)) is True
    assert host_has_arsenal(which=_wh(set()), os_release_path=str(b)) is True


def test_id_like_match(tmp_path):
    f = tmp_path / "os-release"
    f.write_text('ID=mydistro\nID_LIKE="ubuntu kali"\n')
    assert host_has_arsenal(which=_wh(set()), os_release_path=str(f)) is True


def test_ubuntu_no_tools_is_not_arsenal(tmp_path):
    f = tmp_path / "os-release"
    f.write_text('ID=ubuntu\n')
    assert host_has_arsenal(which=_wh(set()), os_release_path=str(f)) is False


def test_tool_quorum_makes_arsenal(tmp_path):
    f = tmp_path / "os-release"
    f.write_text('ID=ubuntu\n')
    assert host_has_arsenal(which=_wh({"nmap", "sqlmap"}), os_release_path=str(f)) is True


def test_only_nmap_is_not_quorum(tmp_path):
    f = tmp_path / "os-release"
    f.write_text('ID=ubuntu\n')
    assert host_has_arsenal(which=_wh({"nmap"}), os_release_path=str(f)) is False


def test_missing_os_release_uses_quorum():
    assert host_has_arsenal(which=_wh({"nmap", "hydra"}), os_release_path="/no/such/file") is True
    assert host_has_arsenal(which=_wh(set()), os_release_path="/no/such/file") is False
