from grin.dockerenv import resolve_docker_host, ensure_docker_host


def test_explicit_docker_host_is_respected():
    env = {"DOCKER_HOST": "tcp://1.2.3.4:2375", "HOME": "/home/x"}
    assert resolve_docker_host(env, exists=lambda p: True) is None


def test_colima_default_socket_preferred():
    env = {"HOME": "/home/x"}
    seen = {"/home/x/.colima/default/docker.sock": True}
    host = resolve_docker_host(env, exists=lambda p: seen.get(p, False))
    assert host == "unix:///home/x/.colima/default/docker.sock"


def test_falls_back_to_standard_socket():
    env = {"HOME": "/home/x"}
    seen = {"/var/run/docker.sock": True}
    assert resolve_docker_host(env, exists=lambda p: seen.get(p, False)) == "unix:///var/run/docker.sock"


def test_none_when_no_socket():
    env = {"HOME": "/home/x"}
    assert resolve_docker_host(env, exists=lambda p: False) is None


def test_ensure_sets_when_unset(monkeypatch, tmp_path):
    sock = tmp_path / ".colima" / "default" / "docker.sock"
    sock.parent.mkdir(parents=True)
    sock.write_text("")
    env = {"HOME": str(tmp_path)}
    host = ensure_docker_host(env)
    assert host == f"unix://{sock}"
    assert env["DOCKER_HOST"] == f"unix://{sock}"


def test_ensure_noop_when_already_set():
    env = {"DOCKER_HOST": "unix:///custom.sock", "HOME": "/home/x"}
    assert ensure_docker_host(env) is None
    assert env["DOCKER_HOST"] == "unix:///custom.sock"
