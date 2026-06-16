from grin.setup.controller import SetupController


def _ctrl(tmp_path, **kw):
    class R: returncode = 0; stdout = ""
    defaults = dict(run=lambda _c: R(), which=lambda t: "/bin/" + t, os_name="macos",
                    env_path=str(tmp_path / "env"))
    defaults.update(kw)
    return SetupController(**defaults)


def test_controller_save_key_writes_env(tmp_path):
    c = _ctrl(tmp_path)
    c.save_key("sk-z", url="https://api.deepseek.com")
    assert "sk-z" in open(tmp_path / "env").read()


def test_controller_docker_status(tmp_path):
    c = _ctrl(tmp_path)
    assert c.docker_status()["running"] is True


def test_controller_install_docker_uses_plan(tmp_path):
    seen = {}
    def run(cmd): seen["cmd"] = cmd; return type("R", (), {"returncode": 0})()
    c = _ctrl(tmp_path, run=run, which=lambda t: "/bin/brew" if t == "brew" else None)
    out = c.install_docker()
    assert out["status"] == "installed"
    assert "--cask" in seen["cmd"]


def test_controller_install_grin(tmp_path):
    src = tmp_path / "Grin.app"; src.mkdir(); (src / "m").write_text("x")
    dest = tmp_path / "Applications"
    c = _ctrl(tmp_path)
    out = c.install_grin(src=str(src), dest=str(dest))
    assert (dest / "Grin.app" / "m").exists() and out["installed_to"].endswith("Grin.app")
