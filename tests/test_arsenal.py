from grin.arsenal import (DEFAULT_ARSENALS, ARSENAL_IMAGES, distro_for,
                          run_container_argv, install_cmd, add_cmd, probe_argv, resolve_tool)


def test_defaults():
    assert DEFAULT_ARSENALS == ("grin-kali", "grin-blackarch")
    assert ARSENAL_IMAGES["grin-kali"].startswith("kalilinux/")
    assert ARSENAL_IMAGES["grin-blackarch"].startswith("blackarchlinux/")


def test_distro_for():
    assert distro_for("grin-kali") == "apt"
    assert distro_for("grin-blackarch") == "pacman"


def test_run_container_argv():
    argv = run_container_argv("grin-kali", "kalilinux/kali-rolling")
    assert argv[:3] == ["docker", "run", "-d"]
    assert "--name" in argv and "grin-kali" in argv
    assert "kalilinux/kali-rolling" in argv
    assert argv[-2:] == ["sleep", "infinity"]


def test_install_cmd_apt_vs_pacman():
    apt = install_cmd("apt", ["nmap", "hydra"])
    assert "apt-get install -y" in apt and "nmap" in apt and "hydra" in apt
    pac = install_cmd("pacman", ["nmap", "hydra"])
    assert "pacman -S" in pac and "--noconfirm" in pac and "nmap" in pac


def test_add_cmd():
    assert "nikto" in add_cmd("apt", "nikto")
    assert "nikto" in add_cmd("pacman", "nikto")


def test_probe_argv():
    argv = probe_argv("grin-kali", "nmap")
    assert argv[:3] == ["docker", "exec", "grin-kali"]
    assert any("command -v nmap" in a for a in argv)


def test_resolve_tool_prefers_first_then_falls_back():
    have = {("grin-kali", "nmap"): True, ("grin-blackarch", "special"): True}
    probe = lambda c, t: have.get((c, t), False)
    assert resolve_tool("nmap", ("grin-kali", "grin-blackarch"), probe) == "grin-kali"
    assert resolve_tool("special", ("grin-kali", "grin-blackarch"), probe) == "grin-blackarch"
    assert resolve_tool("absent", ("grin-kali", "grin-blackarch"), probe) is None
