from grin.mode import resolve_mode, ASSESSMENT, CTF


def test_explicit_assessment_wins_over_target_type():
    assert resolve_mode("assessment", "ip-host") == ASSESSMENT


def test_explicit_ctf_wins_over_weburl():
    assert resolve_mode("ctf", "web-url") == CTF


def test_weburl_target_derives_assessment():
    assert resolve_mode("", "web-url") == ASSESSMENT
    assert resolve_mode(None, "web-url") == ASSESSMENT


def test_default_is_ctf():
    assert resolve_mode("", "ip-host") == CTF
    assert resolve_mode("", "unknown") == CTF
    assert resolve_mode(None, None) == CTF


def test_legacy_own_lab_mode_is_ctf():
    # existing lab engagements use mode: own-lab — must keep CTF (flag-capture) behavior
    assert resolve_mode("own-lab", "ip-host") == CTF


def test_case_insensitive():
    assert resolve_mode("ASSESSMENT", "") == ASSESSMENT
    assert resolve_mode("  Ctf ", "web-url") == CTF
