"""SARIF + HTML report renderers — machine-readable (CI / code-scanning) and human-shareable
output, on top of the existing JSON + Markdown. Pure: no tools, no spine."""
import json

from grin.engagement import validate_engagement
from grin.finding import Finding
from grin.objective import Objective
from grin.orchestrator import EngagementResult
from grin.report import render_html, render_sarif, sarif_level

ENG = validate_engagement({
    "id": "acme", "name": "ACME external", "mode": "client",
    "scope": {"in": ["*.acme.test"], "exclude": ["vpn.acme.test"]},
    "roe": {"allowed_actions": ["passive", "active-scan", "exploit"]},
    "autonomy": "action-gated", "env": {"kind": "local"},
    "audit_log": "./audit/acme.jsonl", "state": "active",
})


def _result(**over):
    base = dict(
        status="completed",
        findings=[
            Finding("SQLi", "www.acme.test", "high", "injectable param id", "sqlmap",
                    "sqlmap -u x", "parameterize queries"),
            Finding("Server banner", "www.acme.test", "info", "nginx 1.18", "whatweb",
                    "whatweb x", ""),
        ],
        objectives_run=[Objective("scan web", "www.acme.test")],
        paused=[],
        plan_log=[],
    )
    base.update(over)
    return EngagementResult(**base)


# ---- SARIF ----------------------------------------------------------------

def test_sarif_level_maps_severity():
    assert sarif_level("critical") == "error"
    assert sarif_level("high") == "error"
    assert sarif_level("medium") == "warning"
    assert sarif_level("low") == "note"
    assert sarif_level("info") == "note"
    assert sarif_level("nonsense") == "note"   # unknown -> safest


def test_sarif_is_valid_2_1_0_with_results():
    doc = json.loads(render_sarif(ENG, _result()))
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Grin"
    assert len(run["results"]) == 2
    r0 = run["results"][0]
    assert r0["level"] == "error"                       # the high finding
    assert "SQLi" in r0["message"]["text"]
    assert r0["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    # every result's ruleId must be defined in the driver's rules (SARIF requirement)
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert all(res["ruleId"] in rule_ids for res in run["results"])


def test_sarif_no_findings_is_empty_results_not_error():
    doc = json.loads(render_sarif(ENG, _result(findings=[])))
    assert doc["runs"][0]["results"] == []


# ---- HTML -----------------------------------------------------------------

def test_html_is_standalone_and_escapes():
    evil = Finding("<script>alert(1)</script>", "www.acme.test", "high",
                   "x & y < z", "burp", "cmd", "fix")
    html = render_html(ENG, _result(findings=[evil]), summary_text="2 findings & counting")
    assert html.lstrip().lower().startswith("<!doctype html")
    assert "ACME external" in html
    # the malicious title/evidence must be HTML-escaped, never live markup
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "x &amp; y &lt; z" in html
    assert "2 findings &amp; counting" in html


def test_html_no_findings_renders():
    html = render_html(ENG, _result(findings=[]), summary_text="no findings")
    assert "No findings" in html
