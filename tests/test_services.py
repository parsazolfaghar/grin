from grin.services import extract_services, extract_live_hosts


PING_SWEEP = """Starting Nmap 7.99 ( https://nmap.org )
Nmap scan report for 192.168.1.1
Host is up (0.0053s latency).
Nmap scan report for 192.168.1.127
Host is up (0.00044s latency).
Nmap scan report for 192.168.1.50
Host is up (0.0011s latency).
Nmap done: 256 IP addresses (3 hosts up) scanned in 2.10 seconds"""


def test_extract_live_hosts_from_ping_sweep():
    assert extract_live_hosts(PING_SWEEP) == ["192.168.1.1", "192.168.1.127", "192.168.1.50"]


def test_extract_live_hosts_resolves_name_to_ip_in_parens():
    out = "Nmap scan report for router.lan (192.168.1.1)\nHost is up (0.005s latency)."
    assert extract_live_hosts(out) == ["192.168.1.1"]


def test_extract_live_hosts_skips_down_and_dedups():
    out = (PING_SWEEP + "\nNmap scan report for 192.168.1.99\nHost seems down.\n"
           + PING_SWEEP)
    hosts = extract_live_hosts(out)
    assert "192.168.1.99" not in hosts
    assert hosts.count("192.168.1.1") == 1


def test_extract_live_hosts_empty_and_none():
    assert extract_live_hosts("") == []
    assert extract_live_hosts(None) == []


NMAP = """Starting Nmap 7.99 ( https://nmap.org )
Nmap scan report for 172.30.0.11
Host is up (0.00020s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian
80/tcp open  http    nginx 1.24
443/tcp closed https
Service detection performed."""


def test_extract_open_services():
    svcs = extract_services(NMAP)
    pairs = {(s.port, s.name) for s in svcs}
    assert (22, "ssh") in pairs
    assert (80, "http") in pairs
    assert all(s.port != 443 for s in svcs)


def test_extract_dedups():
    svcs = extract_services(NMAP + "\n" + NMAP)
    assert sum(1 for s in svcs if s.port == 22) == 1


def test_extract_empty_and_garbage():
    assert extract_services("") == []
    assert extract_services("no ports here") == []
    assert extract_services(None) == []
