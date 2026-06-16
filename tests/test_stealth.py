from grin.stealth import STEALTH_LEVELS, profile_for, apply, StealthProfile


def test_levels():
    assert STEALTH_LEVELS == ("off", "quiet", "paranoid")


def test_profile_off_disables_everything():
    p = profile_for("off", {})
    assert p.level == "off" and p.egress == "" and p.timing == "" and p.device is False


def test_profile_egress_prefers_grin_proxy():
    p = profile_for("quiet", {"GRIN_PROXY": "socks5://1.2.3.4:1080"})
    assert p.egress == "socks5://1.2.3.4:1080"


def test_profile_egress_tor_fallback():
    p = profile_for("quiet", {"GRIN_EGRESS": "tor"})
    assert p.egress == "socks5://127.0.0.1:9050"


def test_profile_no_egress_is_empty():
    p = profile_for("quiet", {})
    assert p.egress == ""


def test_paranoid_enables_device_and_decoys():
    p = profile_for("paranoid", {})
    assert p.device is True and p.decoys is True and p.timing.startswith("-T1")


def test_apply_off_is_identity():
    p = profile_for("off", {"GRIN_PROXY": "socks5://x:1"})
    assert apply(p, "nmap", "nmap -sV 10.0.0.1") == "nmap -sV 10.0.0.1"


def test_apply_egress_wraps_network_tool():
    p = profile_for("quiet", {"GRIN_PROXY": "socks5://x:1"})
    out = apply(p, "nmap", "nmap -sV 10.0.0.1")
    assert out.startswith("proxychains -q nmap")


def test_apply_egress_skips_non_network_tool():
    p = profile_for("quiet", {"GRIN_PROXY": "socks5://x:1"})
    assert apply(p, "cat", "cat /etc/passwd") == "cat /etc/passwd"


def test_apply_injects_nmap_timing_once():
    p = profile_for("quiet", {})
    out = apply(p, "nmap", "nmap -sV 10.0.0.1")
    assert "-T2" in out
    out2 = apply(p, "nmap", "nmap -T4 -sV 10.0.0.1")
    assert out2.count("-T") == 1


def test_apply_paranoid_adds_decoys():
    p = profile_for("paranoid", {})
    out = apply(p, "nmap", "nmap -sV 10.0.0.1")
    assert "-D " in out


def test_apply_curl_user_agent():
    p = profile_for("quiet", {})
    out = apply(p, "curl", "curl http://t/")
    assert "-A " in out
    assert apply(p, "curl", 'curl -A "x" http://t/').count("-A ") == 1


from grin.stealth import can_spoof_device, device_setup


def _wh(present):
    return lambda t: ("/usr/bin/" + t) if t in present else None


def test_can_spoof_requires_local_host_and_macchanger():
    assert can_spoof_device(lambda: True, _wh({"macchanger"})) is True
    assert can_spoof_device(lambda: True, _wh(set())) is False
    assert can_spoof_device(lambda: False, _wh({"macchanger"})) is False


def test_device_setup_returns_commands_when_enabled_and_capable():
    p = profile_for("paranoid", {})
    cmds = device_setup(p, iface="eth0", can_spoof=True)
    assert any(c.startswith("macchanger") and "eth0" in c for c in cmds)


def test_device_setup_empty_when_not_capable_or_disabled():
    p = profile_for("paranoid", {})
    assert device_setup(p, iface="eth0", can_spoof=False) == []
    q = profile_for("quiet", {})
    assert device_setup(q, iface="eth0", can_spoof=True) == []
