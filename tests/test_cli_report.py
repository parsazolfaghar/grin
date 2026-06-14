import json
from grin.cli import cmd_report, cmd_engage, build_parser, main
import grin.cli as cli
from grin.report_store import save_result, result_path
from grin.orchestrator import EngagementResult
from grin.objective import Objective
from grin.finding import Finding
from grin.engagement import load_engagement
from grin.inference import FakeClient
from grin.runner import FakeRunner

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


def test_report_subcommand_parses():
    args = build_parser().parse_args(["report", "e.yaml", "-o", "r.md"])
    assert args.group == "report"
    assert args.out == "r.md"


def test_cmd_report_writes_markdown(tmp_path, monkeypatch):
    path = _write_eng(tmp_path)
    eng = load_engagement(path)
    save_result(result_path(eng), EngagementResult(
        status="completed",
        findings=[Finding("Open port", "203.0.113.7", "info", "80 open", "nmap",
                          "nmap -sV x", "")],
        objectives_run=[Objective("enumerate", "203.0.113.0/24")],
        paused=[], plan_log=[]))
    monkeypatch.setattr(cli, "_make_client", lambda eng: FakeClient("x", up=False))
    out_file = str(tmp_path / "report.md")
    rc = cmd_report(path, out=out_file, model="m")
    assert rc == 0
    md = open(out_file).read()
    assert "# Grin Engagement Report" in md
    assert "Open port" in md


def test_cmd_report_no_saved_result_errors(tmp_path, capsys):
    path = _write_eng(tmp_path)
    rc = cmd_report(path, out=None, model="m")
    assert rc != 0
    assert "engage" in capsys.readouterr().err.lower()


def test_engage_saves_result_for_reporting(tmp_path, monkeypatch):
    path = _write_eng(tmp_path)
    monkeypatch.setattr(cli, "_make_client",
                        lambda eng: FakeClient(json.dumps({"objectives": []})))
    monkeypatch.setattr(cli, "_make_executor_client", lambda eng: FakeClient("x"))
    monkeypatch.setattr(cli, "_runner_for", lambda eng: FakeRunner())
    rc = cmd_engage(path, goal="g", seeds="", model="m", max_objectives=10, max_steps=12)
    assert rc == 0
    eng = load_engagement(path)
    import os
    assert os.path.exists(result_path(eng))


def test_main_dispatches_report(tmp_path, monkeypatch):
    path = _write_eng(tmp_path)
    eng = load_engagement(path)
    save_result(result_path(eng), EngagementResult(status="completed", findings=[],
                objectives_run=[], paused=[], plan_log=[]))
    monkeypatch.setattr(cli, "_make_client", lambda eng: FakeClient("x", up=False))
    assert main(["report", path]) == 0


def test_cmd_report_corrupted_result_errors(tmp_path, capsys):
    path = _write_eng(tmp_path)
    eng = load_engagement(path)
    from pathlib import Path
    rp = result_path(eng)
    Path(rp).parent.mkdir(parents=True, exist_ok=True)
    Path(rp).write_text("{ not valid json")
    rc = cmd_report(path, out=None, model="m")
    assert rc != 0
    assert "engage" in capsys.readouterr().err.lower()
