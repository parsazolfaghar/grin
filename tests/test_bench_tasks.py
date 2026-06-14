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

def test_exploit_case_names_authorized_target_and_expects_tools():
    ex = [c for c in default_cases() if c.role == "exploit"][0]
    _sys, user = ex.build()
    assert ex.expect.get("exploit_tools")
    assert any(t in user.lower() for t in ("target", "in-scope", "authorized"))

def test_recon_extract_case_has_evidence_keywords_in_history():
    rx = [c for c in default_cases() if c.name == "recon-extract"][0]
    _sys, user = rx.build()
    # the canned observation must be in the prompt history
    assert any(k in user.lower() for k in rx.expect["evidence"])
