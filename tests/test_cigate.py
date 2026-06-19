from grin.cigate import ci_gate, meets_threshold
from grin.finding import Finding


def _f(sev, title="x"):
    return Finding(title, "t", sev, "ev", "tool", "cmd", "")


def test_meets_threshold_at_or_above():
    # critical is the most severe; fail_on='high' must trip on high AND critical, not on medium.
    assert meets_threshold("critical", "high") is True
    assert meets_threshold("high", "high") is True
    assert meets_threshold("medium", "high") is False
    assert meets_threshold("info", "info") is True
    assert meets_threshold("low", "info") is True   # low is above info


def test_meets_threshold_unknown_severity_does_not_trip():
    assert meets_threshold("weird", "high") is False


def test_ci_gate_fails_with_exit_2_when_offending_present():
    code, offending, summary = ci_gate([_f("high"), _f("info")], fail_on="high")
    assert code == 2
    assert len(offending) == 1 and offending[0].severity == "high"
    assert "high" in summary


def test_ci_gate_passes_with_exit_0_when_below_threshold():
    code, offending, summary = ci_gate([_f("low"), _f("info")], fail_on="high")
    assert code == 0
    assert offending == []
    assert "pass" in summary.lower()


def test_ci_gate_no_findings_passes():
    code, offending, summary = ci_gate([], fail_on="low")
    assert code == 0 and offending == []
