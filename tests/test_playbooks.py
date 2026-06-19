import pytest

from grin.engagement import validate_engagement
from grin.playbooks import PLAYBOOKS, PlaybookError, build_engagement, playbook_names


def test_lists_the_expected_playbooks():
    names = playbook_names()
    assert names == sorted(names)  # stable, sorted
    for expected in ("recon-only", "external-asm", "internal-network", "bug-bounty", "ctf-solver"):
        assert expected in names
        assert expected in PLAYBOOKS


def test_unknown_playbook_raises():
    with pytest.raises(PlaybookError):
        build_engagement("does-not-exist", eid="x", name="X", scope_in=["t"])


def test_every_playbook_produces_a_valid_engagement():
    for name in playbook_names():
        data = build_engagement(name, eid="e1", name="Test", scope_in=["10.0.0.0/24"],
                                scope_exclude=["10.0.0.1"])
        eng = validate_engagement(data)        # must not raise
        assert eng.id == "e1"
        assert eng.scope.include == ["10.0.0.0/24"]
        assert eng.scope.exclude == ["10.0.0.1"]
        assert eng.state == "active"
        assert eng.audit_log.endswith("e1.jsonl")


def test_recon_only_is_passive_and_gated():
    eng = validate_engagement(build_engagement("recon-only", eid="r", name="R", scope_in=["t"]))
    assert eng.roe.allowed_actions == ["passive"]
    assert eng.autonomy == "action-gated"
    assert eng.strength == "recon"


def test_ctf_solver_is_full_auto_and_aggressive():
    eng = validate_engagement(build_engagement("ctf-solver", eid="c", name="C", scope_in=["t"]))
    assert eng.autonomy == "autonomous"
    assert eng.strength == "aggressive"
    assert "exploit" in eng.roe.allowed_actions and "post-exploit" in eng.roe.allowed_actions


def test_env_override_is_honored():
    data = build_engagement("ctf-solver", eid="c", name="C", scope_in=["t"],
                            env={"kind": "arsenal"})
    assert data["env"]["kind"] == "arsenal"
