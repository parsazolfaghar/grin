from pathlib import Path
from grin.catalog import load_catalog
from grin.report import attack_coverage
from grin.finding import Finding

CAT = str(Path(__file__).resolve().parents[1] / "catalog" / "attack_catalog.yaml")


def test_attack_coverage_attempted_and_succeeded():
    cat = load_catalog(CAT)
    audit = [
        {"decision": "allow", "tool": "nmap", "command": "nmap -sV 10.0.0.5"},
        {"decision": "allow", "tool": "hydra", "command": "hydra ssh://10.0.0.5"},
    ]
    findings = [Finding(title="weak ssh", target="10.0.0.5", severity="high",
                        evidence="cracked", tool="hydra", command="hydra ...")]
    cov = attack_coverage(cat, audit, findings)
    assert "T1595" in cov["attempted"]
    assert "T1110" in cov["attempted"] and "T1110" in cov["succeeded"]
    assert "T1595" not in cov["succeeded"]


def test_attack_coverage_empty():
    cat = load_catalog(CAT)
    cov = attack_coverage(cat, [], [])
    assert cov["attempted"] == [] and cov["succeeded"] == []


def test_render_report_includes_attack_section_when_catalog_passed():
    from grin.report import render_report
    from grin.orchestrator import EngagementResult
    from grin.engagement import validate_engagement
    cat = load_catalog(CAT)
    eng = validate_engagement({
        "id": "test-eng", "name": "Test Engagement", "mode": "client",
        "scope": {"in": ["10.0.0.5"], "exclude": []},
        "roe": {"allowed_actions": ["passive", "active-scan", "exploit"]},
        "autonomy": "action-gated", "env": {"kind": "local"},
        "audit_log": "./audit/test.jsonl", "state": "active",
    })
    res = EngagementResult(
        "completed",
        [Finding("weak ssh", "10.0.0.5", "high", "x", "hydra", "c", "")],
        [], [], [],
        goal="g",
    )
    audit = [{"decision": "allow", "tool": "hydra", "command": "hydra ssh://10.0.0.5"}]
    md = render_report(eng, res, audit_summary="", summary_text="",
                       catalog=cat, audit_records=audit)
    assert "ATT&CK Coverage" in md and "T1110" in md
