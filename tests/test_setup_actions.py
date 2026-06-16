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
