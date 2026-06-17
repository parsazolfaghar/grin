import json
from pathlib import Path
from grin.app.api import GrinApi
from grin.inference import FakeClient
from grin.finding import Finding
from grin.orchestrator import EngagementResult
from grin.report_store import save_result, result_path
from grin.engagement import load_engagement

EXAMPLE = """
id: t-app
name: app test
mode: own-lab
scope:
  include: ["127.0.0.1"]
  exclude: []
roe:
  allowed_actions: ["passive", "active-scan"]
  windows: []
autonomy: autonomous
env:
  kind: local
audit_log: "{audit}"
state: active
"""

def _write_eng(tmp_path):
    audit = str(tmp_path / "t-app.audit.jsonl")
    f = tmp_path / "t-app.yaml"
    f.write_text(EXAMPLE.format(audit=audit))
    return str(f)

def test_list_engagements_valid_and_invalid(tmp_path):
    _write_eng(tmp_path)
    (tmp_path / "broken.yaml").write_text("id: only-id\n")
    api = GrinApi(engagements_dir=str(tmp_path))
    rows = api.list_engagements()
    valid = [r for r in rows if r.get("valid")]
    assert any(r["id"] == "t-app" and r["mode"] == "own-lab" for r in valid)
    assert any(r.get("valid") is False for r in rows)  # broken.yaml
    json.dumps(rows)

def test_doctor_returns_report_dict(tmp_path):
    api = GrinApi(engagements_dir=str(tmp_path),
                  ollama=FakeClient(up=True, models=["qwen3:14b"]))
    rep = api.doctor()
    assert "platform" in rep and "checks" in rep and "ok" in rep
    json.dumps(rep)

def test_findings_from_saved_result(tmp_path):
    path = _write_eng(tmp_path)
    eng = load_engagement(path)
    res = EngagementResult(status="completed",
                           findings=[Finding("sqli", "127.0.0.1", "high", "ev", "sqlmap", "cmd", "fix")])
    save_result(result_path(eng), res)
    api = GrinApi(engagements_dir=str(tmp_path))
    fs = api.findings(path)
    assert fs[0]["title"] == "sqli" and fs[0]["severity"] == "high"
    json.dumps(fs)

def test_findings_missing_result_is_empty(tmp_path):
    path = _write_eng(tmp_path)
    api = GrinApi(engagements_dir=str(tmp_path))
    assert api.findings(path) == []

def test_loot_and_audit_and_blocked_are_lists(tmp_path):
    path = _write_eng(tmp_path)
    api = GrinApi(engagements_dir=str(tmp_path))
    assert api.loot(path) == []           # no loot dir yet
    assert api.audit(path) == []          # no audit lines yet
    assert api.blocked(path) == []        # no pending yet
    json.dumps([api.loot(path), api.audit(path), api.blocked(path)])

def test_audit_tail_parsed(tmp_path):
    path = _write_eng(tmp_path)
    eng = load_engagement(path)
    line = {"ts": "2026-06-13T20:00:00Z", "target": "127.0.0.1", "tool": "nmap",
            "command": "nmap -sV 127.0.0.1", "action_class": "active-scan", "decision": "allow"}
    Path(eng.audit_log).parent.mkdir(parents=True, exist_ok=True)
    Path(eng.audit_log).write_text(json.dumps(line) + "\n")
    api = GrinApi(engagements_dir=str(tmp_path))
    rows = api.audit(path)
    assert rows[0]["decision"] == "allow" and rows[0]["tool"] == "nmap"

def test_bad_path_returns_error_not_raise(tmp_path):
    api = GrinApi(engagements_dir=str(tmp_path))
    assert "error" in api.findings(str(tmp_path / "nope.yaml")) if isinstance(api.findings(str(tmp_path / "nope.yaml")), dict) else api.findings(str(tmp_path / "nope.yaml")) == []


def test_discoveries_reads_results_store(tmp_path):
    from grin.results import ResultStore, results_path
    path = _write_eng(tmp_path)
    eng = load_engagement(path)
    out = ("Nmap scan report for 127.0.0.1\n7000/tcp open airplay\n"
           "GRIN{abc123}\n")
    ResultStore(results_path(eng)).put(id="r1", command="nmap -sV 127.0.0.1",
                                       output=out, exit_code=0)
    api = GrinApi(engagements_dir=str(tmp_path))
    d = api.discoveries(path)
    assert d["commands_run"] == 1
    assert d["hosts"][0]["target"] == "127.0.0.1"
    assert d["hosts"][0]["services"][0]["port"] == 7000
    assert d["flags"][0]["value"] == "GRIN{abc123}"
    json.dumps(d)


def test_discoveries_missing_store_is_empty(tmp_path):
    path = _write_eng(tmp_path)
    api = GrinApi(engagements_dir=str(tmp_path))
    d = api.discoveries(path)
    assert d["hosts"] == [] and d["commands_run"] == 0


def test_merged_snapshot_includes_discovered(tmp_path):
    path = _write_eng(tmp_path)
    api = GrinApi(engagements_dir=str(tmp_path))
    snap = api._merged_snapshot(path)
    assert "discovered" in snap
    json.dumps(snap)
