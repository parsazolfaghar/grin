from grin.services import extract_services


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
