import json

from grin.discoveries import (discover, target_from_command, summary_line,
                              gather_records)


def _rec(command, output, id="x"):
    return {"id": id, "command": command, "output": output, "exit_code": 0}


def test_explicit_target_wins_over_command_parsing():
    # journal steps carry action.target; honor it even when the command has a different/no host
    d = discover([{"command": "nmap -sV scanme", "output": "22/tcp open ssh\n",
                   "target": "10.9.9.9"}])
    assert d.hosts[0].target == "10.9.9.9"


def test_ping_sweep_surfaces_live_hosts_with_no_open_ports():
    # a -sn sweep finds live hosts but no ports; they must still appear in Discoveries
    out = ("Nmap scan report for 192.168.1.1\nHost is up (0.005s latency).\n"
           "Nmap scan report for your-rig\nHost is up (0.001s latency).\n")
    d = discover([_rec("nmap -sn 192.168.1.0/24", out)])
    targets = {h.target for h in d.hosts}
    assert "192.168.1.1" in targets and "your-rig" in targets
    assert all(h.services == [] for h in d.hosts)  # live, no open ports


def test_filtered_port_scan_still_surfaces_the_host():
    # every port filtered (no 'open') -> 0 services, but the host is live and must show up
    out = ("Nmap scan report for 192.168.1.127\nHost is up (0.0004s latency).\n"
           "22/tcp filtered ssh\n80/tcp filtered http\n")
    d = discover([_rec("nmap -sV -p 22,80 192.168.1.127", out)])
    assert any(h.target == "192.168.1.127" and h.services == [] for h in d.hosts)


class _Eng:
    def __init__(self, audit_log):
        self.audit_log = audit_log


def _write_journal(base, task_id, steps):
    path = f"{base}.{task_id}.journal.json"
    json_data = {"task_id": task_id, "objective": "o", "target": "t",
                 "engagement_path": "e.yaml", "path": path, "steps": steps}
    open(path, "w").write(json.dumps(json_data))


def test_gather_records_reads_journals(tmp_path):
    base = str(tmp_path / "eng.audit")
    _write_journal(base, "aaa", [
        {"action": {"tool": "nmap", "command": "nmap -sV 10.0.0.5", "target": "10.0.0.5"},
         "decision": "executed", "output": "22/tcp open ssh\n", "exit_code": 0},
        {"action": {"tool": "hydra", "command": "hydra ssh", "target": "10.0.0.5"},
         "decision": "refused", "output": "", "exit_code": None}])  # refused -> skipped
    recs = gather_records(_Eng(base + ".jsonl"))
    assert len(recs) == 1
    assert recs[0]["command"] == "nmap -sV 10.0.0.5"
    assert recs[0]["target"] == "10.0.0.5"
    d = discover(recs)
    assert d.hosts[0].target == "10.0.0.5"
    assert d.hosts[0].services[0].port == 22


def test_gather_records_merges_results_store_and_journals(tmp_path):
    from grin.results import ResultStore, results_path
    base = str(tmp_path / "eng.audit")
    eng = _Eng(base + ".jsonl")
    ResultStore(results_path(eng)).put(id="r1", command="nmap 10.0.0.1",
                                       output="80/tcp open http\n", exit_code=0)
    _write_journal(base, "bbb", [
        {"action": {"tool": "nmap", "command": "nmap 10.0.0.2", "target": "10.0.0.2"},
         "decision": "executed", "output": "443/tcp open https\n", "exit_code": 0}])
    d = discover(gather_records(eng))
    targets = {h.target for h in d.hosts}
    assert targets == {"10.0.0.1", "10.0.0.2"}


def test_gather_records_no_files_is_empty(tmp_path):
    assert gather_records(_Eng(str(tmp_path / "nope.jsonl"))) == []


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
