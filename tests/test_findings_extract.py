from grin.extractors import extract_findings


def test_parse_nuclei_default_lines():
    out = (
        "[CVE-2021-44228] [http] [critical] http://t/api/log [apache-log4j]\n"
        "[tomcat-default-login] [http] [high] http://t:8080/manager/html\n"
        "[ssl-dns-names] [ssl] [info] t:443\n"
        "garbage line that is not a finding\n"
    )
    fs = extract_findings("nuclei", "nuclei -u http://t", out, "t")
    titles = [f.title for f in fs]
    assert "CVE-2021-44228" in titles
    assert "tomcat-default-login" in titles
    sev = {f.title: f.severity for f in fs}
    assert sev["CVE-2021-44228"] == "critical"
    assert sev["tomcat-default-login"] == "high"
    # evidence carries the matched URL + tool
    crit = next(f for f in fs if f.title == "CVE-2021-44228")
    assert "http://t/api/log" in crit.evidence and crit.tool == "nuclei"


def test_parse_nuclei_dedups_repeats():
    out = ("[x-frame] [http] [info] http://t/\n"
           "[x-frame] [http] [info] http://t/\n")
    fs = extract_findings("nuclei", "nuclei -u http://t", out, "t")
    assert len([f for f in fs if f.title == "x-frame"]) == 1


def test_extract_findings_non_nuclei_tool_is_empty():
    assert extract_findings("nmap", "nmap -sV t", "22/tcp open ssh", "t") == []


def test_extract_findings_never_raises_on_junk():
    assert extract_findings("nuclei", "", None, "t") == []
    assert extract_findings("nuclei", "", "", "t") == []


def test_extract_bac_probe_findings_carry_class_and_location():
    out = ("bac-probe http://t/ (unauthenticated) — 1 finding(s)\n"
           "HIT /ftp/legal.md 200 sensitive content served without authentication\n")
    fs = extract_findings("bac-probe", "bac-probe --url http://t/", out, "http://t")
    assert len(fs) == 1
    f = fs[0]
    assert f.vuln_class == "broken-access-control"
    assert f.location == "/ftp/legal.md"
    assert "/ftp/legal.md" in f.evidence and "200" in f.evidence


def test_extract_bac_probe_no_hits_is_empty():
    out = "bac-probe http://t/ (unauthenticated) — 0 finding(s)\n"
    assert extract_findings("bac-probe", "bac-probe --url http://t/", out, "http://t") == []


def test_extract_idor_findings():
    out = ("idor-probe http://t/ (as a@b.c) — 1 finding(s)\n"
           "IDOR http://t/rest/basket/2 200 victim data reachable across users\n")
    fs = extract_findings("idor-probe", "idor-probe --url http://t/", out, "http://t")
    assert len(fs) == 1
    assert fs[0].vuln_class == "idor" and fs[0].location == "/rest/basket/2"


def test_extract_sqli_findings():
    out = ("sqli-probe http://t/rest/user/login — 1 finding(s)\n"
           "SQLI http://t/rest/user/login ' OR 1=1-- authentication bypass\n")
    fs = extract_findings("sqli-probe", "sqli-probe --url http://t/", out, "http://t")
    assert len(fs) == 1
    assert fs[0].vuln_class == "sql-injection" and fs[0].location == "/rest/user/login"
