from grin.engine import assess
from grin.verify import Candidate, Transport


def _ssti(path):
    return Candidate(vuln_class="ssti", location=f"{path} (param q)",
                     url=f"http://t{path}", inject_field="q")


def test_assess_emits_findings_only_for_confirmed():
    # /a is vulnerable (evaluates the payload); /b is not
    def request(method, url, json=None, headers=None):
        if "/a" in url:
            return (200, "7006652") if "1234" in url else (200, "control")
        return (200, "nothing here")
    findings = assess([_ssti("/a"), _ssti("/b")], Transport(request=request))
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_class == "ssti" and "/a" in f.location
    assert f.location and f.evidence            # carries the verdict's evidence


def test_assess_sets_severity_by_class():
    def request(method, url, json=None, headers=None):
        return (200, "7006652") if "1234" in url else (200, "control")
    findings = assess([_ssti("/a")], Transport(request=request))
    assert findings[0].severity in ("critical", "high")   # ssti is high-impact


def test_assess_empty_when_nothing_confirms():
    assert assess([_ssti("/a")], Transport(request=lambda *a, **k: (200, "no"))) == []


def test_assess_inconclusive_is_not_a_finding():
    # a verifier that can't tell (error status) must NOT produce a finding
    assert assess([_ssti("/a")], Transport(request=lambda *a, **k: (500, ""))) == []


from grin.engine import recon


def test_recon_generates_bac_sqli_ssti_candidates():
    def fetch(url):
        return (200, '<form action="/x"><input name="search"><input name="comment"></form>')
    cands = recon("http://t:3000", fetch)
    classes = {c.vuln_class for c in cands}
    assert {"broken-access-control", "sql-injection", "ssti"} <= classes
    # the discovered form param became an SSTI candidate
    assert any(c.vuln_class == "ssti" and c.inject_field == "search" for c in cands)
    # BAC candidates carry a baseline_url for the SPA-shell diff
    bac = [c for c in cands if c.vuln_class == "broken-access-control"][0]
    assert bac.oracle.get("baseline_url")
    # the SQLi candidate targets the login as a POST on the email field
    sqli = [c for c in cands if c.vuln_class == "sql-injection"][0]
    assert sqli.method == "POST" and sqli.inject_field == "email" and "login" in sqli.url


def test_recon_survives_unreachable_page():
    def fetch(url):
        raise RuntimeError("down")
    cands = recon("http://t", fetch)
    # still yields BAC + SQLi candidates from the static lists even if the page won't load
    assert {"broken-access-control", "sql-injection"} <= {c.vuln_class for c in cands}
