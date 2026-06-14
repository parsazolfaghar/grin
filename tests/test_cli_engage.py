import json
from ronin.cli import cmd_engage, build_parser, main
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
    return str(p)


def test_engage_subcommand_parses():
    args = build_parser().parse_args(
        ["engage", "e.yaml", "--goal", "assess network", "--seeds", "a,b", "--max-objectives", "5"])
    assert args.group == "engage"
    assert args.goal == "assess network"
    assert args.seeds == "a,b"
    assert args.max_objectives == 5


def test_cmd_engage_runs_and_reports(tmp_path, capsys, monkeypatch):
    path = _write_eng(tmp_path)
    planner = FakeClient([
        json.dumps({"objectives": [{"objective": "enumerate", "target": "203.0.113.0/24"}]}),
        json.dumps({"done": True, "reason": "done", "next_objectives": []}),
    ])
    # The executor must run an action before reporting findings (evidence gate).
    executor = FakeClient([
        json.dumps({"action": {"tool": "nmap", "command": "nmap -sn 203.0.113.0/24",
                               "target": "203.0.113.0/24", "declared_class": "active-scan",
                               "why": "enumerate"}}),
        json.dumps({"done": True, "findings": [
            {"title": "host up", "severity": "info", "evidence": ".7", "tool": "nmap",
             "command": "nmap -sn 203.0.113.0/24"}]}),
    ])
    monkeypatch.setattr(cli, "_make_client", lambda eng: planner)
    monkeypatch.setattr(cli, "_make_executor_client", lambda eng: executor)
    monkeypatch.setattr(cli, "_runner_for",
                        lambda eng: FakeRunner({"nmap -sn 203.0.113.0/24":
                                                ExecResult(".7 up", 0, 0.1, False)}))
    rc = cmd_engage(path, goal="assess network", seeds="", model="m", max_objectives=10,
                    max_steps=12)
    assert rc == 0
    out = capsys.readouterr().out
    assert "completed" in out.lower()
    assert "host up" in out


def test_main_dispatches_engage(tmp_path, monkeypatch):
    path = _write_eng(tmp_path)
    monkeypatch.setattr(cli, "_make_client",
                        lambda eng: FakeClient(json.dumps({"objectives": []})))
    monkeypatch.setattr(cli, "_make_executor_client", lambda eng: FakeClient("x"))
    monkeypatch.setattr(cli, "_runner_for", lambda eng: FakeRunner())
    assert main(["engage", path, "--goal", "g"]) == 0
