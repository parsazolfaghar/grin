from grin.honeypot import assess, TrapAssessment
from grin.finding import Finding


def _f(title, evidence, target="t", tool="nmap"):
    return Finding(title=title, target=target, severity="info", evidence=evidence,
                   tool=tool, command="nmap -sV", recommendation="")


def test_clean_findings_not_suspected():
    a = assess([_f("OpenSSH", "22/tcp open ssh OpenSSH 10.3")])
    assert not a.suspected and a.score == 0 and a.signals == []


def test_fingerprint_flags_suspected():
    a = assess([_f("SSH", "22/tcp open ssh — banner: Cowrie SSH honeypot")])
    assert a.suspected and a.score >= 40
    assert any("cowrie" in s for s in a.signals)


def test_fingerprint_in_audit_lines():
    a = assess([], audit_lines=[{"command": "nc dionaea-host 21", "tool": "nc"}])
    assert a.suspected and any("dionaea" in s for s in a.signals)


def test_implausible_open_ports_flagged():
    findings = [_f(f"port {p}", f"{p}/tcp open svc", target="10.0.0.9") for p in range(20)]
    a = assess(findings)
    assert any("implausibly many" in s for s in a.signals)


def test_advisory_only_returns_assessment_not_block():
    # the detector only describes; it never raises/blocks
    a = assess([_f("x", "cowrie")])
    assert isinstance(a, TrapAssessment) and a.detail.startswith("SUSPECTED")


def test_jsonable_shape():
    import dataclasses
    a = assess([_f("SSH", "kippo honeypot detected")])
    d = dataclasses.asdict(a)
    assert d["suspected"] is True and isinstance(d["signals"], list)
