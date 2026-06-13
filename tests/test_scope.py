from ronin.scope import in_scope


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
