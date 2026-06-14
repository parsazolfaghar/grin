import json
from ronin.report import (
    SEVERITY_ORDER, deterministic_summary, summarize_audit, llm_summary, render_report,
)
from ronin.orchestrator import EngagementResult
from ronin.objective import Objective
from ronin.finding import Finding
from ronin.inference import FakeClient
from ronin.engagement import validate_engagement

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
            Finding("SQLi", "www.acme.test", "high", "injectable", "sqlmap", "sqlmap -u x", "parameterize"),
            Finding("Server banner", "www.acme.test", "info", "nginx 1.18", "whatweb", "whatweb x", ""),
        ],
        objectives_run=[Objective("enumerate", "*.acme.test"),
                        Objective("scan web", "www.acme.test")],
        paused=[{"objective": Objective("exploit ssh", "10.0.0.5"), "pending_id": "pid9",
                 "journal": "/tmp/j.json"}],
        plan_log=[{"kind": "initial_plan", "objectives": [Objective("enumerate", "*.acme.test")]},
                  {"kind": "replan", "done": False, "reason": "found a web host",
                   "objectives": [Objective("scan web", "www.acme.test")]},
                  {"kind": "replan", "done": True, "reason": "goal met", "objectives": []}],
    )
    base.update(over)
    return EngagementResult(**base)


def test_severity_order():
    assert SEVERITY_ORDER == ("critical", "high", "medium", "low", "info")


def test_deterministic_summary_counts():
    s = deterministic_summary(_result())
    assert "2 findings" in s
    assert "1 high" in s
    assert "1 info" in s
    assert "2 objectives" in s
    assert "1 blocked" in s


def test_deterministic_summary_no_findings():
    s = deterministic_summary(_result(findings=[]))
    assert "no findings" in s.lower()


def test_summarize_audit_counts(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in [
        {"decision": "allow"}, {"decision": "allow"}, {"decision": "refuse"}]) + "\n")
    s = summarize_audit(str(p))
    assert "3 actions" in s
    assert "2 allowed" in s
    assert "1 refused" in s


def test_summarize_audit_missing_file(tmp_path):
    assert "no audit log" in summarize_audit(str(tmp_path / "nope.jsonl")).lower()


def test_llm_summary_falls_back_when_model_down():
    r = _result()
    assert llm_summary(FakeClient("ignored", up=False), "m", r) == deterministic_summary(r)


def test_llm_summary_falls_back_on_empty_reply():
    r = _result()
    assert llm_summary(FakeClient("   "), "m", r) == deterministic_summary(r)


def test_llm_summary_uses_model_reply():
    r = _result()
    assert llm_summary(FakeClient("The external host exposes a SQL injection."), "m", r) \
        == "The external host exposes a SQL injection."


def test_render_report_has_all_sections_and_findings():
    md = render_report(ENG, _result(), audit_summary="3 actions logged: 2 allowed, 1 refused.",
                       summary_text="Two findings, one high.")
    assert "# Ronin Engagement Report" in md
    assert "ACME external" in md
    assert "Two findings, one high." in md
    assert "## Findings" in md
    assert "SQLi" in md and "www.acme.test" in md
    assert "sqlmap -u x" in md
    assert "parameterize" in md
    assert md.index("high") < md.index("info")
    assert "## Methodology" in md
    assert "enumerate" in md and "found a web host" in md
    assert "## Blocked / awaiting approval" in md
    assert "exploit ssh" in md and "pid9" in md
    assert "## Appendix" in md
    assert "2 allowed, 1 refused" in md


def test_render_report_no_findings():
    md = render_report(ENG, _result(findings=[]), audit_summary="(no audit log)",
                       summary_text="No findings.")
    assert "No findings." in md


def test_render_report_includes_unknown_severity_findings():
    r = _result(findings=[Finding("Weird thing", "h", "bogus-sev", "e", "tool", "cmd", "")])
    md = render_report(ENG, r, audit_summary="x", summary_text="s")
    assert "Weird thing" in md   # an unexpected severity must NOT be silently dropped


def test_deterministic_summary_singular_grammar():
    r = _result(findings=[Finding("One", "h", "high", "e", "t", "c", "")],
                objectives_run=[Objective("o", "t")], paused=[])
    s = deterministic_summary(r)
    assert "1 finding (" in s
    assert "across 1 objective;" in s
    assert "findings" not in s and "objectives" not in s


def test_llm_summary_falls_back_on_exception():
    class _Exploder:
        def is_up(self): return True
        def generate(self, **kw): raise RuntimeError("boom")
    r = _result()
    assert llm_summary(_Exploder(), "m", r) == deterministic_summary(r)
