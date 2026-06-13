import json
from datetime import datetime
from ronin.cli import main, cmd_validate, cmd_audit, run_loop
from ronin.engagement import load_engagement
from ronin.runner import FakeRunner, ExecResult

ENG_YAML = """
id: e1
name: n
mode: own-lab
scope:
  in: ["10.0.0.0/24"]
roe:
  allowed_actions: [passive, active-scan]
autonomy: autonomous
env: {{kind: local}}
audit_log: {audit}
state: active
"""


def _write_eng(tmp_path):
    audit = str(tmp_path / "audit" / "e1.jsonl")
    p = tmp_path / "e1.yaml"
    p.write_text(ENG_YAML.format(audit=audit))
    return str(p), audit


def test_validate_ok(tmp_path, capsys):
    path, _ = _write_eng(tmp_path)
    rc = cmd_validate(path)
    assert rc == 0
    assert "e1" in capsys.readouterr().out


def test_validate_bad_file_returns_nonzero(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: x\n")
    rc = cmd_validate(str(bad))
    assert rc != 0


def test_run_loop_processes_actions_and_audits(tmp_path):
    path, audit = _write_eng(tmp_path)
    eng = load_engagement(path)
    runner = FakeRunner({"nmap -sV 10.0.0.5": ExecResult("80/open", 0, 0.5, False)})
    lines = ["nmap | nmap -sV 10.0.0.5 | 10.0.0.5 | active-scan"]
    run_loop(eng, runner=runner, now=datetime(2026, 1, 1), lines=iter(lines))
    recs = [json.loads(l) for l in open(audit).read().splitlines()]
    assert len(recs) == 1
    assert recs[0]["decision"] == "allow"
    assert recs[0]["tool"] == "nmap"


def test_audit_prints_trail(tmp_path, capsys):
    path, audit = _write_eng(tmp_path)
    eng = load_engagement(path)
    run_loop(eng, runner=FakeRunner(), now=datetime(2026, 1, 1),
             lines=iter(["nmap | nmap 10.0.0.5 | 10.0.0.5 | active-scan"]))
    rc = cmd_audit(path)
    assert rc == 0
    assert "10.0.0.5" in capsys.readouterr().out


def test_main_dispatches_validate(tmp_path):
    path, _ = _write_eng(tmp_path)
    assert main(["engagement", "validate", path]) == 0
