from grin.doctor import (Check, Fix, DoctorReport, check_engine_deps, check_ollama,
                         check_models)
from grin.platform_info import PlatformInfo
from grin.inference import FakeClient

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
