from grin.assessment import assessment_sweep


def test_assessment_sweep_runs_all_probes_and_extracts_findings():
    def run_action(tool, command):
        if "bac-probe" in command:
            return "bac-probe — 1 finding(s)\nHIT /ftp/legal.md 200 served without auth"
        if "sqli-probe" in command:
            return "sqli — 1\nSQLI http://t:3000/rest/user/login ' OR 1=1-- bypass"
        if "idor-probe" in command:
            return "idor — 1\nIDOR http://t:3000/rest/basket/7 200 cross-user object access"
        return ""
    creds = [{"email": "a@x", "password": "p1"}, {"email": "b@x", "password": "p2"}]
    findings = assessment_sweep("http://t:3000", creds, run_action, "http://t:3000")
    classes = sorted({f.vuln_class for f in findings})
    assert classes == ["broken-access-control", "idor", "sql-injection"]


def test_assessment_sweep_no_base_url_is_empty():
    assert assessment_sweep("", [], lambda t, c: "should-not-run", "") == []


def test_assessment_sweep_no_creds_skips_idor():
    def run_action(tool, command):
        return "HIT /ftp/x 200 y" if "bac-probe" in command else ""
    findings = assessment_sweep("http://t:3000", [], run_action, "http://t:3000")
    assert {f.vuln_class for f in findings} == {"broken-access-control"}   # no idor without creds
