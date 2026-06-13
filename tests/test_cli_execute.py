import json
from ronin.cli import cmd_execute, build_parser, main
from ronin.results import ResultStore, results_path
from ronin.engagement import load_engagement
import ronin.cli as cli
from ronin.inference import FakeClient
from ronin.runner import FakeRunner, ExecResult

ENG_YAML = """
id: e1
name: n
mode: own-lab
scope:
  in: ["203.0.113.0/24"]
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


def test_execute_subcommand_parses():
    args = build_parser().parse_args(
        ["execute", "e.yaml", "--task", "find web", "--target", "203.0.113.7"])
    assert args.group == "execute"
    assert args.task == "find web"
    assert args.target == "203.0.113.7"


def test_cmd_execute_runs_loop_and_reports(tmp_path, capsys, monkeypatch):
    path, audit = _write_eng(tmp_path)
    replies = [
        json.dumps({"action": {"tool": "nmap", "command": "nmap -sV 203.0.113.7",
                               "target": "203.0.113.7", "declared_class": "active-scan",
                               "why": "x"}}),
        json.dumps({"done": True, "findings": [{"title": "nginx", "severity": "info",
                    "evidence": "80", "tool": "nmap", "command": "nmap -sV 203.0.113.7"}]}),
    ]
    monkeypatch.setattr(cli, "_make_client", lambda eng: FakeClient(replies))
    monkeypatch.setattr(cli, "_runner_for",
                        lambda eng: FakeRunner({"nmap -sV 203.0.113.7":
                                                ExecResult("80/tcp open", 0, 0.1, False)}))
    rc = cmd_execute(path, task="find web", target="203.0.113.7", model="m", max_steps=12)
    assert rc == 0
    out = capsys.readouterr().out
    assert "completed" in out.lower()
    assert "nginx" in out


def test_main_dispatches_execute(tmp_path, monkeypatch):
    path, _ = _write_eng(tmp_path)
    monkeypatch.setattr(cli, "_make_client",
                        lambda eng: FakeClient(json.dumps({"done": True, "findings": []})))
    monkeypatch.setattr(cli, "_runner_for", lambda eng: FakeRunner())
    assert main(["execute", path, "--task", "o", "--target", "203.0.113.7"]) == 0
