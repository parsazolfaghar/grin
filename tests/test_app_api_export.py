import json
from pathlib import Path

from grin.app.api import GrinApi
from grin.engagement import load_engagement
from grin.finding import Finding
from grin.orchestrator import EngagementResult
from grin.report_store import result_path, save_result

EXAMPLE = """
id: t-app
name: app test
mode: own-lab
scope:
  in: ["127.0.0.1"]
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


def _eng_with_result(tmp_path):
    audit = str(tmp_path / "t-app.audit.jsonl")
    f = tmp_path / "t-app.yaml"
    f.write_text(EXAMPLE.format(audit=audit))
    eng = load_engagement(str(f))
    res = EngagementResult(status="completed",
                           findings=[Finding("SQLi", "127.0.0.1", "high", "injectable id",
                                             "sqlmap", "sqlmap -u x", "parameterize")])
    save_result(result_path(eng), res)
    return str(f)


def test_export_html(tmp_path):
    path = _eng_with_result(tmp_path)
    api = GrinApi(engagements_dir=str(tmp_path))
    out = str(tmp_path / "report.html")
    res = api.export_report(path, "html", out)
    assert res.get("status") == "written" and res["format"] == "html"
    body = Path(out).read_text()
    assert body.lstrip().lower().startswith("<!doctype html") and "SQLi" in body
    json.dumps(res)


def test_export_sarif_is_valid_json(tmp_path):
    path = _eng_with_result(tmp_path)
    api = GrinApi(engagements_dir=str(tmp_path))
    out = str(tmp_path / "report.sarif")
    api.export_report(path, "sarif", out)
    doc = json.loads(Path(out).read_text())
    assert doc["version"] == "2.1.0" and doc["runs"][0]["results"]


def test_export_markdown(tmp_path):
    path = _eng_with_result(tmp_path)
    api = GrinApi(engagements_dir=str(tmp_path))
    out = str(tmp_path / "report.md")
    api.export_report(path, "markdown", out)
    assert "# Grin Engagement Report" in Path(out).read_text()


def test_export_no_result_is_friendly_error(tmp_path):
    # engagement file exists but no run has happened -> a clear message, never a raised exception
    f = tmp_path / "t-app.yaml"
    f.write_text(EXAMPLE.format(audit=str(tmp_path / "a.jsonl")))
    api = GrinApi(engagements_dir=str(tmp_path))
    res = api.export_report(str(f), "html", str(tmp_path / "x.html"))
    assert "error" in res
    json.dumps(res)
