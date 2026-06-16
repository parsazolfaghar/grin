import os
import stat
from grin.setup.actions import write_env, docker_status


def test_write_env_content_and_perms(tmp_path):
    p = tmp_path / "env"
    write_env(str(p), api_key="sk-abc", url="https://api.deepseek.com")
    text = p.read_text()
    assert "GRIN_MODEL_BACKEND=openai" in text
    assert "GRIN_MODEL_URL=https://api.deepseek.com" in text
    assert "GRIN_MODEL_API_KEY=sk-abc" in text
    if os.name == "posix":
        assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_docker_status_not_installed():
    def which(_t): return None
    def run(_cmd): raise AssertionError("must not run docker when absent")
    assert docker_status(run, which) == {"installed": False, "running": False}


def test_docker_status_installed_running():
    def which(t): return "/usr/bin/docker" if t == "docker" else None
    class R: returncode = 0; stdout = ""
    assert docker_status(lambda _c: R(), which) == {"installed": True, "running": True}


def test_docker_status_installed_not_running():
    def which(t): return "/usr/bin/docker"
    class R: returncode = 1; stdout = "Cannot connect to the Docker daemon"
    assert docker_status(lambda _c: R(), which) == {"installed": True, "running": False}


from grin.setup.actions import docker_install_plan, run_install_plan


def _which(present):
    return lambda t: ("/bin/" + t) if t in present else None


def test_plan_macos_brew_auto():
    p = docker_install_plan("macos", _which({"brew"}))
    assert p["mode"] == "auto" and p["command"][:3] == ["brew", "install", "--cask"]


def test_plan_macos_no_brew_guide():
    p = docker_install_plan("macos", _which(set()))
    assert p["mode"] == "guide" and "docker.com" in p["note"]


def test_plan_windows_winget_auto():
    p = docker_install_plan("windows", _which({"winget"}))
    assert p["mode"] == "auto" and "Docker.DockerDesktop" in " ".join(p["command"])


def test_plan_linux_script_auto():
    p = docker_install_plan("linux", _which({"curl"}))
    assert p["mode"] == "auto" and "get.docker.com" in " ".join(p["command"])


def test_plan_unknown_guide():
    assert docker_install_plan("unknown", _which({"brew"}))["mode"] == "guide"


def test_run_install_plan_guide_passthrough():
    out = run_install_plan({"mode": "guide", "command": [], "note": "do X"}, lambda _c: None)
    assert out["status"] == "guide" and out["note"] == "do X"


def test_run_install_plan_auto_success():
    class R: returncode = 0
    out = run_install_plan({"mode": "auto", "command": ["x"], "note": ""}, lambda _c: R())
    assert out["status"] == "installed"


def test_run_install_plan_auto_failure():
    class R: returncode = 7
    out = run_install_plan({"mode": "auto", "command": ["x"], "note": ""}, lambda _c: R())
    assert out["status"] == "failed"


from grin.setup.actions import install_grin, provision_arsenal


def test_install_grin_copies_into_dest(tmp_path):
    src = tmp_path / "Grin.app"; (src / "Contents").mkdir(parents=True)
    (src / "Contents" / "marker").write_text("x")
    dest = tmp_path / "Applications"; dest.mkdir()
    out = install_grin("macos", src=str(src), dest=str(dest))
    placed = dest / "Grin.app"
    assert placed.exists() and (placed / "Contents" / "marker").read_text() == "x"
    assert out["installed_to"] == str(placed)


def test_install_grin_replaces_existing(tmp_path):
    src = tmp_path / "Grin.app"; src.mkdir(); (src / "new").write_text("new")
    dest = tmp_path / "Applications"; (dest / "Grin.app").mkdir(parents=True)
    (dest / "Grin.app" / "old").write_text("old")
    install_grin("macos", src=str(src), dest=str(dest))
    assert (dest / "Grin.app" / "new").exists()
    assert not (dest / "Grin.app" / "old").exists()


def test_provision_arsenal_runs_arsenal_up():
    calls = []
    class R: returncode = 0
    provision_arsenal(lambda cmd: calls.append(cmd) or R())
    assert any("arsenal" in c and "up" in c for c in calls)
