from ronin.finding import Finding, normalize_severity, SEVERITIES


def test_severities_ordered():
    assert SEVERITIES == ("info", "low", "medium", "high", "critical")


def test_normalize_known_and_unknown():
    assert normalize_severity("HIGH") == "high"
    assert normalize_severity("  Critical ") == "critical"
    assert normalize_severity("bogus") == "info"     # fail-soft default
    assert normalize_severity(None) == "info"
    assert normalize_severity("") == "info"


def test_finding_is_value_equal():
    a = Finding(title="t", target="h", severity="low", evidence="e", tool="nmap", command="c")
    b = Finding(title="t", target="h", severity="low", evidence="e", tool="nmap", command="c")
    assert a == b
    assert a.recommendation == ""     # optional default
