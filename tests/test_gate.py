from ronin.gate import gate, INTRUSIVE


def test_intrusive_set():
    assert INTRUSIVE == {"exploit", "post-exploit"}


def test_autonomous_runs_everything():
    assert gate("passive", "autonomous") == "run"
    assert gate("exploit", "autonomous") == "run"
    assert gate("post-exploit", "autonomous") == "run"


def test_action_gated_holds_intrusive_runs_rest():
    assert gate("passive", "action-gated") == "run"
    assert gate("active-scan", "action-gated") == "run"
    assert gate("exploit", "action-gated") == "pending"
    assert gate("post-exploit", "action-gated") == "pending"


def test_phase_gated_pends_until_phase_approved():
    assert gate("active-scan", "phase-gated") == "run"
    assert gate("exploit", "phase-gated") == "pending"
    assert gate("exploit", "phase-gated", approved_phases=("exploit",)) == "run"


def test_unknown_mode_fails_closed_to_pending():
    assert gate("passive", "wat") == "pending"
