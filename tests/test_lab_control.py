from grin.lab.control import (compose_argv, reset_argv, reachable_argv, LAB_CONTAINERS)


def test_compose_up_argv():
    argv = compose_argv("up", "/x/lab/docker-compose.yml")
    assert argv[:3] == ["docker", "compose", "-f"]
    assert "/x/lab/docker-compose.yml" in argv
    assert argv[-2:] == ["up", "-d"]


def test_compose_down_argv():
    argv = compose_argv("down", "/x/lab/docker-compose.yml")
    assert argv[-1] == "down"


def test_reset_argv_restarts_all_targets():
    argv = reset_argv()
    assert argv[:2] == ["docker", "restart"]
    assert set(argv[2:]) == set(LAB_CONTAINERS)


def test_reachable_argv_uses_runner_exec_and_nmap():
    argv = reachable_argv("grin-kali", "172.30.0.11", 22)
    assert argv[:3] == ["docker", "exec", "grin-kali"]
    assert "nmap" in argv and "172.30.0.11" in argv and "-p22" in argv
