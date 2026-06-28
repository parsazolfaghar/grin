from grin.finding import Finding, normalize_severity, SEVERITIES


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


def test_finding_optional_vuln_fields_default_empty():
    f = Finding(title="t", target="h", severity="low", evidence="e", tool="nmap", command="c")
    assert f.vuln_class == ""
    assert f.location == ""


def test_finding_vuln_fields_settable_and_roundtrip():
    from dataclasses import asdict
    f = Finding(title="t", target="h", severity="high", evidence="e", tool="nmap",
                command="c", vuln_class="broken-access-control", location="/rest/basket/{id}")
    assert f.vuln_class == "broken-access-control"
    assert f.location == "/rest/basket/{id}"
    # round-trips via asdict -> Finding(**) exactly as report_store/journal do
    assert Finding(**asdict(f)) == f


def test_finding_roundtrip_from_legacy_dict_without_new_fields():
    # old serialized findings (pre-extension) must still reconstruct with defaults
    legacy = {"title": "t", "target": "h", "severity": "low", "evidence": "e",
              "tool": "nmap", "command": "c", "recommendation": ""}
    f = Finding(**legacy)
    assert f.vuln_class == "" and f.location == ""
