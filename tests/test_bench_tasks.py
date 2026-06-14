from grin.bench.tasks import default_cases, _StubJournal, BenchCase

def test_stub_journal_returns_canned_history():
    j = _StubJournal("OUTPUT: 22/tcp open ssh")
    assert "22/tcp" in j.render_history()

def test_default_cases_cover_three_roles():
    cases = default_cases()
    roles = {c.role for c in cases}
    assert roles == {"planner", "recon", "exploit"}
    for c in cases:
        sys_, user = c.build()
        assert isinstance(sys_, str) and sys_
        assert isinstance(user, str) and user

def test_exploit_battery_has_multiple_scenarios_each_with_right_tools():
    ex = [c for c in default_cases() if c.role == "exploit"]
    assert len(ex) >= 5
    names = {c.name for c in ex}
    assert {"exploit-sqli", "exploit-weak-creds", "exploit-known-cve",
            "exploit-web-rce", "exploit-postexploit"} <= names
    for c in ex:
        _sys, user = c.build()
        assert c.expect.get("right"), f"{c.name} missing right toolset"
        assert any(t in user.lower() for t in ("target", "in-scope", "authorized", "203.0", "acme"))

def test_postexploit_case_allows_post_exploit_and_seeds_shell():
    pe = [c for c in default_cases() if c.name == "exploit-postexploit"][0]
    _sys, user = pe.build()
    assert "post-exploit" in user.lower()
    assert "shell" in user.lower()

def test_recon_extract_case_has_evidence_keywords_in_history():
    rx = [c for c in default_cases() if c.name == "recon-extract"][0]
    _sys, user = rx.build()
    # the canned observation must be in the prompt history
    assert any(k in user.lower() for k in rx.expect["evidence"])
