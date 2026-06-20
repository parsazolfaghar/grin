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
