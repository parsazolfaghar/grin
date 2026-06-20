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


def test_install_cmd_tolerant_isolates_each_package():
    # tolerant mode must install packages one-by-one and swallow per-package failures so one bad
    # name can't abort the whole batch (the pacman whole-transaction-abort bug).
    pac = install_cmd("pacman", ["nmap", "boguspkg", "hydra"], tolerant=True)
    assert pac.count("|| true") == 3
    assert "pacman -Sy --noconfirm;" in pac
    apt = install_cmd("apt", ["nmap", "boguspkg"], tolerant=True)
    assert apt.count("|| true") == 2
    # non-tolerant default keeps the single-shot form (so add_cmd still gets a real exit code)
    assert "|| true" not in install_cmd("pacman", ["nmap"])


def test_pacman_baseline_has_no_known_bad_names():
    from grin.arsenal import BASELINE
    assert "gnu-netcat" not in BASELINE["pacman"]      # not in synced repos
    assert "wordlists" not in BASELINE["pacman"]       # no such pacman package
    assert "openbsd-netcat" in BASELINE["pacman"]      # the correct Arch netcat


def test_helpers_map_covers_every_tools_module():
    # guard: every runnable helper in grin/tools/ must be in HELPERS so `arsenal deploy` (and updates)
    # push it into the containers — otherwise a new closer ships but never reaches the arsenal.
    import os
    from grin.arsenal import HELPERS
    tools_dir = os.path.join(os.path.dirname(__import__("grin").__file__), "tools")
    modules = {f[:-3] for f in os.listdir(tools_dir)
               if f.endswith(".py") and f != "__init__.py"}
    assert modules == set(HELPERS), f"HELPERS out of sync with grin/tools: {modules ^ set(HELPERS)}"


def test_arsenals_are_complementary_hydra_blackarch_only():
    # the two arsenals must NOT be redundant: hydra/medusa live only on BlackArch so brute-force
    # routes there, verifying grin reaches both arsenals during a real run.
    from grin.arsenal import BASELINE, BLACKARCH_ONLY
    assert "hydra" not in BASELINE["apt"]
    assert "hydra" in BASELINE["pacman"]
    assert "hydra" in BLACKARCH_ONLY
    # the common recon tool stays on Kali (so most tools still resolve to Kali first)
    assert "nmap" in BASELINE["apt"]


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
