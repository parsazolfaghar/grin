from grin.doctor import (Check, Fix, DoctorReport, check_engine_deps, check_ollama,
                         check_models, check_env, check_tools, run_doctor)
from grin.platform_info import PlatformInfo
from grin.inference import FakeClient
from grin.engagement import Engagement, Scope, ROE
from grin.runner import FakeRunner, ExecResult

PLAT = PlatformInfo(os="linux", raw="Linux", host_pkg_mgr="apt")

def test_engine_deps_present_when_importable():
    # pyyaml + httpx are real deps of the project, so they import
    checks = check_engine_deps(want_docker=False)
    assert all(c.status == "ok" for c in checks if c.name != "engine dep: docker")
    # docker is skipped when not wanted
    docker = [c for c in checks if c.name == "engine dep: docker"][0]
    assert docker.status == "skipped"

def test_engine_deps_docker_checked_when_wanted():
    checks = check_engine_deps(want_docker=True)
    docker = [c for c in checks if c.name == "engine dep: docker"][0]
    # docker SDK may or may not be installed here; either checked-ok or broken-with-fix, never skipped
    assert docker.status in ("ok", "broken")
    if docker.status == "broken":
        assert docker.fix is not None and docker.fix.runner == "pip"

def test_ollama_up():
    c = check_ollama(FakeClient(up=True))
    assert c.status == "ok" and c.fix is None

def test_ollama_down_is_broken_with_advisory_fix():
    c = check_ollama(FakeClient(up=False))
    assert c.status == "broken"
    assert c.fix is not None and c.fix.kind == "advisory"

def test_models_missing_gets_auto_pull_fix():
    client = FakeClient(up=True, models=["qwen3:14b"])
    checks = check_models(client, ["qwen3:14b", "hermes3:8b"])
    by = {c.name: c for c in checks}
    assert by["model qwen3:14b"].status == "ok"
    miss = by["model hermes3:8b"]
    assert miss.status == "missing"
    assert miss.fix.kind == "auto" and miss.fix.runner == "ollama"
    assert "hermes3:8b" in miss.fix.command

def test_models_skipped_when_daemon_down():
    checks = check_models(FakeClient(up=False), ["qwen3:14b"])
    assert all(c.status == "skipped" for c in checks)

def test_report_ok_and_fixable():
    ok = Check(name="a", status="ok", detail="")
    miss = Check(name="b", status="missing", detail="",
                 fix=Fix(label="x", command="y", kind="auto", runner="ollama"))
    adv = Check(name="c", status="broken", detail="",
                fix=Fix(label="x", command="y", kind="advisory", runner="ollama"))
    rep = DoctorReport(platform=PLAT, checks=[ok, miss, adv])
    assert rep.ok is False
    assert [c.name for c in rep.fixable()] == ["b"]
    assert DoctorReport(platform=PLAT, checks=[ok]).ok is True


def _eng(env):
    return Engagement(id="e", name="e", mode="own-lab", scope=Scope(["127.0.0.1"], []),
                      roe=ROE(["passive"], []), autonomy="autonomous", env=env,
                      audit_log="/tmp/a.jsonl", state="active")

def test_env_local_is_ok():
    checks = check_env(_eng({"kind": "local"}), ssh_prober=None, docker_prober=None)
    assert len(checks) == 1 and checks[0].status == "ok"

def test_env_ssh_unreachable_is_advisory():
    checks = check_env(_eng({"kind": "ssh", "ssh_host": "root@10.0.0.9"}),
                       ssh_prober=lambda host: False, docker_prober=None)
    assert checks[0].status == "broken"
    assert checks[0].fix.kind == "advisory"

def test_env_ssh_reachable_ok():
    checks = check_env(_eng({"kind": "ssh", "ssh_host": "root@127.0.0.1"}),
                       ssh_prober=lambda host: True, docker_prober=None)
    assert checks[0].status == "ok"

def test_env_docker_missing_container_advisory():
    checks = check_env(_eng({"kind": "docker", "container": "grin-kali"}), ssh_prober=None,
                       docker_prober=lambda c: {"daemon": True, "container": False})
    names = {c.name: c for c in checks}
    assert names["docker daemon"].status == "ok"
    cont = [c for c in checks if c.name.startswith("docker container")][0]
    assert cont.status == "missing" and cont.fix.kind == "advisory"

def test_tools_missing_inside_env_gets_auto_env_fix():
    # command -v nmap -> exit 1 (missing); command -v whois -> exit 0 (present)
    runner = FakeRunner({"command -v nmap": ExecResult("", 1, 0.0, False),
                         "command -v whois": ExecResult("/usr/bin/whois", 0, 0.0, False)})
    eng = _eng({"kind": "docker", "container": "grin-kali"})
    checks = check_tools(eng, runner, ["nmap", "whois"])
    by = {c.name: c for c in checks}
    assert by["tool: whois"].status == "ok"
    assert by["tool: nmap"].status == "missing"
    assert by["tool: nmap"].fix.kind == "auto" and by["tool: nmap"].fix.runner == "env"
    assert "nmap" in by["tool: nmap"].fix.command

def test_run_doctor_assembles_report():
    from grin.platform_info import PlatformInfo
    from grin.inference import FakeClient
    plat = PlatformInfo("linux", "Linux", "apt")
    rep = run_doctor(platform=plat, ollama=FakeClient(up=True, models=["qwen3:14b"]),
                     engagement=None, runner=None, required_models=["qwen3:14b"], tools=["nmap"])
    assert rep.platform is plat
    names = [c.name for c in rep.checks]
    assert names[0] == "OS"
    assert any(n.startswith("engine dep") for n in names)
    assert "Ollama daemon" in names
    assert "model qwen3:14b" in names
    # no engagement -> no env/tool checks
    assert not any(n.startswith("tool:") for n in names)


def test_check_env_auto_reports_local(monkeypatch):
    from grin.doctor import check_env
    from grin.engagement import Engagement, Scope, ROE
    monkeypatch.setattr("grin.platform_info.host_has_arsenal", lambda *a, **k: True)
    eng = Engagement(id="x", name="x", mode="adhoc", scope=Scope(["t"]), roe=ROE([]),
                     autonomy="autonomous", env={"kind": "auto"}, audit_log="a", state="active")
    checks = check_env(eng, ssh_prober=None, docker_prober=None)
    assert any("auto" in c.name and "local" in c.detail.lower() for c in checks)


def test_check_env_auto_reports_docker(monkeypatch):
    from grin.doctor import check_env
    from grin.engagement import Engagement, Scope, ROE
    monkeypatch.setattr("grin.platform_info.host_has_arsenal", lambda *a, **k: False)
    eng = Engagement(id="x", name="x", mode="adhoc", scope=Scope(["t"]), roe=ROE([]),
                     autonomy="autonomous", env={"kind": "auto"}, audit_log="a", state="active")
    checks = check_env(eng, ssh_prober=None, docker_prober=None)
    assert any("auto" in c.name and "docker" in c.detail.lower() for c in checks)


def test_check_stealth_warns_without_egress():
    from grin.doctor import check_stealth
    from grin.engagement import Engagement, Scope, ROE
    eng = Engagement(id="x", name="x", mode="adhoc", scope=Scope(["t"]), roe=ROE([]),
                     autonomy="autonomous", env={"kind": "local"}, audit_log="a", state="active",
                     stealth="quiet")
    checks = check_stealth(eng, env={})
    assert any(c.status == "warn" or "no egress" in c.detail.lower() for c in checks)


def test_check_stealth_off_is_skipped():
    from grin.doctor import check_stealth
    from grin.engagement import Engagement, Scope, ROE
    eng = Engagement(id="x", name="x", mode="adhoc", scope=Scope(["t"]), roe=ROE([]),
                     autonomy="autonomous", env={"kind": "local"}, audit_log="a", state="active")
    assert check_stealth(eng, env={}) == []


def test_check_stealth_reports_egress():
    from grin.doctor import check_stealth
    from grin.engagement import Engagement, Scope, ROE
    eng = Engagement(id="x", name="x", mode="adhoc", scope=Scope(["t"]), roe=ROE([]),
                     autonomy="autonomous", env={"kind": "local"}, audit_log="a", state="active",
                     stealth="paranoid")
    checks = check_stealth(eng, env={"GRIN_PROXY": "socks5://1.2.3.4:1080"})
    assert any("1.2.3.4" in c.detail for c in checks)


def test_check_tools_handles_runner_that_raises():
    from grin.doctor import check_tools
    from grin.engagement import Engagement, Scope, ROE

    class BoomRunner:
        def run(self, target, command, timeout=60):
            raise RuntimeError("409 container not running")

    eng = Engagement(id="x", name="x", mode="adhoc", scope=Scope(["t"]), roe=ROE([]),
                     autonomy="autonomous", env={"kind": "docker", "container": "c"},
                     audit_log="a", state="active")
    checks = check_tools(eng, BoomRunner(), ["nmap"])     # must not raise
    assert checks[0].status == "broken"
    assert "not reachable" in checks[0].detail.lower()
