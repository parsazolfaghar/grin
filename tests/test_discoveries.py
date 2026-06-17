from grin.discoveries import discover, target_from_command, summary_line


def _rec(command, output, id="x"):
    return {"id": id, "command": command, "output": output, "exit_code": 0}


def test_services_extracted_and_attributed_to_target():
    nmap = "Nmap scan report for 192.168.1.42\n7000/tcp open airplay\n8009/tcp open tcpwrapped\n"
    d = discover([_rec("nmap -sV 192.168.1.42", nmap)])
    assert len(d.hosts) == 1
    h = d.hosts[0]
    assert h.target == "192.168.1.42"
    assert [(s.port, s.name) for s in h.services] == [(7000, "airplay"), (8009, "tcpwrapped")]
    assert d.commands_run == 1


def test_services_deduped_across_records_same_target():
    nmap = "22/tcp open ssh\n"
    d = discover([_rec("nmap a 10.0.0.5", nmap, id="1"), _rec("nmap b 10.0.0.5", nmap, id="2")])
    assert len(d.hosts) == 1
    assert [(s.port, s.name) for s in d.hosts[0].services] == [(22, "ssh")]


def test_credentials_and_flags_surfaced():
    out = "[22][ssh] host: 10.0.0.5 login: admin password: hunter2\nGRIN{abc123}\n"
    d = discover([_rec("hydra ssh://10.0.0.5", out)])
    assert any(c.value == "admin:hunter2" for c in d.credentials)
    assert any(f.value == "GRIN{abc123}" for f in d.flags)


def test_target_from_command_variants():
    assert target_from_command("nmap -sV 192.168.1.42") == "192.168.1.42"
    assert target_from_command("curl http://shop.test/x") == "shop.test"
    assert target_from_command("hydra -l a ssh://host.local") == "host.local"
    assert target_from_command("echo hi") == ""


def test_empty_and_junk_never_raise():
    assert discover([]).hosts == []
    assert discover(None).commands_run == 0
    assert discover([{"output": None}]).hosts == []


def test_summary_line():
    d = discover([_rec("nmap -sV 1.2.3.4", "80/tcp open http\n")])
    assert "1 host" in summary_line(d)
    assert "cmd" in summary_line(d)
