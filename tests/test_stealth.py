from grin.stealth import STEALTH_LEVELS, profile_for, apply


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


def test_device_setup_rejects_unsafe_iface():
    p = profile_for("paranoid", {})
    import pytest as _pt
    with _pt.raises(ValueError):
        device_setup(p, iface="eth0; rm -rf /", can_spoof=True)


def test_ua_no_seed_is_default():
    from grin.stealth import profile_for, DEFAULT_UA
    assert profile_for("quiet", {}).ua == DEFAULT_UA


def test_ua_seed_picks_from_pool_and_is_stable():
    from grin.stealth import profile_for, UA_POOL
    a = profile_for("quiet", {}, seed="eng-1").ua
    b = profile_for("quiet", {}, seed="eng-1").ua
    assert a == b                 # stable within a run (same engagement)
    assert a in UA_POOL


def test_ua_rotates_across_engagements():
    from grin.stealth import profile_for
    seen = {profile_for("paranoid", {}, seed=f"eng-{i}").ua for i in range(20)}
    assert len(seen) > 1          # different engagements get different UAs


def test_spine_seeds_ua_per_engagement(tmp_path):
    # the spine seeds profile_for with eng.id, so a curl command carries a pool UA, run-stable
    from grin.spine import _execute_and_audit
    from grin.engagement import Engagement, Scope, ROE
    from grin.stealth import UA_POOL

    class CapRunner:
        def __init__(self): self.cmd = None
        def run(self, target, command, timeout=60):
            self.cmd = command
            class R: exit_code = 0; output = ""; duration_s = 0.0
            return R()

    eng = Engagement(id="eng-xyz", name="e", mode="adhoc", scope=Scope(["t"]), roe=ROE([]),
                     autonomy="autonomous", env={"kind": "local"},
                     audit_log=str(tmp_path / "a.jsonl"), state="active", stealth="quiet")
    r = CapRunner()
    _execute_and_audit(eng, target="t", tool="curl", command="curl http://t/",
                       action_class="active-scan", gated=False, approved_by=None, runner=r)
    assert any(ua in r.cmd for ua in UA_POOL)     # a pool UA was injected via the eng.id seed


def test_ua_pool_env_override(monkeypatch):
    from grin.stealth import profile_for
    monkeypatch.setenv("GRIN_UA_POOL", "UA-One, UA-Two")
    picks = {profile_for("quiet", {}, seed=f"e{i}").ua for i in range(20)}
    assert picks <= {"UA-One", "UA-Two"} and len(picks) >= 1   # only the custom pool is used
