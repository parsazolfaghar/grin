import json
from datetime import datetime
from grin.cli import cmd_engage_resume, build_parser, main
import grin.cli as cli
from grin.orchestrator import orchestrate
from grin.engagement import load_engagement
from grin.report_store import save_result, load_result, result_path
from grin.results import ResultStore, results_path
from grin.inference import FakeClient
from grin.runner import FakeRunner

ENG_YAML = """
id: e1
name: n
mode: client
scope:
  in: ["127.0.0.1"]
roe:
  allowed_actions: [passive, active-scan, exploit]
autonomy: action-gated
env: {{kind: local}}
audit_log: {audit}
state: active
"""


def _write_eng(tmp_path):
    audit = str(tmp_path / "audit" / "e1.jsonl")
    p = tmp_path / "e1.yaml"
    p.write_text(ENG_YAML.format(audit=audit))
    return str(p)


def _plan(objs):
    return json.dumps({"objectives": [{"objective": o, "target": t} for o, t in objs]})


def _replan(done, objs=(), reason="r"):
    return json.dumps({"done": done, "reason": reason,
                       "next_objectives": [{"objective": o, "target": t} for o, t in objs]})


def _ex_action(tool, command, target, cls):
    return json.dumps({"action": {"tool": tool, "command": command, "target": target,
                                  "declared_class": cls, "why": "x"}})


def _ex_done(findings):
    return json.dumps({"done": True, "findings": findings})


def _make_paused(tmp_path, path):
    eng = load_engagement(path)
    prior = orchestrate(eng, goal="assess 127.0.0.1",
                        planner_client=FakeClient([_plan([("exploit", "127.0.0.1")])]),
                        executor_client=FakeClient([_ex_action("sqlmap", "sqlmap -u http://127.0.0.1",
                                                               "127.0.0.1", "exploit")]),
                        runner=FakeRunner(), now=datetime(2026, 1, 1), max_objectives=3,
                        engagement_path=path)
    save_result(result_path(eng), prior)
    return eng, prior


def test_resume_flag_parses():
    args = build_parser().parse_args(["engage", "e.yaml", "--resume"])
    assert args.group == "engage" and args.resume is True


def test_resume_no_saved_result_errors(tmp_path, capsys):
    path = _write_eng(tmp_path)
    rc = cmd_engage_resume(path, model="m", max_objectives=10, max_steps=12)
    assert rc != 0
    assert "engage" in capsys.readouterr().err.lower()


def test_resume_nothing_approved_reports(tmp_path, capsys):
    path = _write_eng(tmp_path)
    _make_paused(tmp_path, path)
    rc = cmd_engage_resume(path, model="m", max_objectives=10, max_steps=12)
    assert rc == 0
    assert "nothing to resume" in capsys.readouterr().out.lower()


def test_resume_runs_after_approval(tmp_path, capsys, monkeypatch):
    path = _write_eng(tmp_path)
    eng, prior = _make_paused(tmp_path, path)
    pid = prior.paused[0]["pending_id"]
    ResultStore(results_path(eng)).put(id=pid, command="sqlmap -u http://127.0.0.1",
                                       output="injectable", exit_code=0)
    monkeypatch.setattr(cli, "_make_client", lambda eng: FakeClient([_replan(True, [], "done")]))
    monkeypatch.setattr(cli, "_make_executor_client",
                        lambda eng: FakeClient([_ex_done([{"title": "SQLi", "severity": "high",
                            "evidence": "x", "tool": "sqlmap", "command": "sqlmap -u http://127.0.0.1"}])]))
    monkeypatch.setattr(cli, "_runner_for", lambda eng: FakeRunner())
    rc = cmd_engage_resume(path, model="m", max_objectives=3, max_steps=6)
    assert rc == 0
    out = capsys.readouterr().out
    assert "completed" in out.lower() and "SQLi" in out
    assert load_result(result_path(eng)).paused == []


def test_main_dispatches_resume(tmp_path):
    path = _write_eng(tmp_path)
    _make_paused(tmp_path, path)
    assert main(["engage", path, "--resume"]) == 0
