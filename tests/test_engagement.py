import textwrap
import pytest
from datetime import datetime
from grin.engagement import (
    Engagement, load_engagement, validate_engagement, EngagementError, pending_path,
)

VALID = {
    "id": "acme-extnet-2026-06",
    "name": "ACME external network",
    "mode": "client",
    "scope": {"in": ["*.acme.test", "203.0.113.0/24"], "exclude": ["vpn.acme.test"]},
    "roe": {"allowed_actions": ["passive", "active-scan", "exploit"],
            "windows": [{"start": "2026-06-13T18:00", "end": "2026-06-14T06:00"}]},
    "autonomy": "action-gated",
    "env": {"kind": "ssh", "ssh_host": "kali@10.0.0.50"},
    "audit_log": "./audit/acme.jsonl",
    "state": "active",
}


def test_validate_returns_engagement():
    eng = validate_engagement(VALID)
    assert isinstance(eng, Engagement)
    assert eng.id == "acme-extnet-2026-06"
    assert eng.scope.include == ["*.acme.test", "203.0.113.0/24"]
    assert eng.scope.exclude == ["vpn.acme.test"]
    assert eng.roe.allowed_actions == ["passive", "active-scan", "exploit"]
    assert eng.roe.windows[0].start == datetime(2026, 6, 13, 18, 0)
    assert eng.autonomy == "action-gated"
    assert eng.env == {"kind": "ssh", "ssh_host": "kali@10.0.0.50"}
    assert eng.state == "active"


def test_missing_required_field_refused():
    bad = dict(VALID); del bad["id"]
    with pytest.raises(EngagementError):
        validate_engagement(bad)


def test_invalid_mode_refused():
    bad = dict(VALID); bad["mode"] = "production"
    with pytest.raises(EngagementError):
        validate_engagement(bad)


def test_invalid_autonomy_refused():
    bad = dict(VALID); bad["autonomy"] = "yolo"
    with pytest.raises(EngagementError):
        validate_engagement(bad)


def test_invalid_state_refused():
    bad = dict(VALID); bad["state"] = "running"
    with pytest.raises(EngagementError):
        validate_engagement(bad)


def test_unknown_roe_action_class_refused():
    bad = dict(VALID)
    bad["roe"] = {"allowed_actions": ["passive", "nuke"], "windows": []}
    with pytest.raises(EngagementError):
        validate_engagement(bad)


def test_unparseable_window_refused():
    bad = dict(VALID)
    bad["roe"] = {"allowed_actions": ["passive"],
                  "windows": [{"start": "not-a-date", "end": "2026-06-14T06:00"}]}
    with pytest.raises(EngagementError):
        validate_engagement(bad)


def test_empty_windows_allowed():
    ok = dict(VALID)
    ok["roe"] = {"allowed_actions": ["passive"], "windows": []}
    eng = validate_engagement(ok)
    assert eng.roe.windows == []


def test_load_engagement_from_yaml(tmp_path):
    p = tmp_path / "eng.yaml"
    p.write_text(textwrap.dedent("""
        id: lab-01
        name: home lab
        mode: own-lab
        scope:
          in: ["10.0.0.0/24"]
        roe:
          allowed_actions: [passive, active-scan]
        autonomy: autonomous
        env: {kind: local}
        audit_log: ./audit/lab-01.jsonl
        state: active
    """))
    eng = load_engagement(str(p))
    assert eng.id == "lab-01"
    assert eng.scope.exclude == []
    assert eng.roe.windows == []


def test_load_missing_file_refused(tmp_path):
    with pytest.raises(EngagementError):
        load_engagement(str(tmp_path / "nope.yaml"))


def test_pending_path_derives_from_audit_log():
    eng = validate_engagement(VALID)
    assert pending_path(eng) == "./audit/acme.state.json"


def test_adhoc_is_a_valid_mode(tmp_path):
    import yaml
    from grin.engagement import load_engagement
    p = tmp_path / "e.yaml"
    p.write_text(yaml.safe_dump({
        "id": "adhoc-x", "name": "x", "mode": "adhoc",
        "scope": {"in": ["10.0.0.1"]},
        "roe": {"allowed_actions": ["passive"]},
        "autonomy": "autonomous", "env": {"kind": "local"},
        "audit_log": str(tmp_path / "a.jsonl"), "state": "active",
    }))
    eng = load_engagement(str(p))
    assert eng.mode == "adhoc"


def test_stealth_defaults_off_and_validates(tmp_path):
    import yaml
    from grin.engagement import load_engagement, EngagementError
    base = {"id": "s", "name": "s", "mode": "adhoc", "scope": {"in": ["t"]},
            "roe": {"allowed_actions": ["passive"]}, "autonomy": "autonomous",
            "env": {"kind": "local"}, "audit_log": str(tmp_path / "a.jsonl"), "state": "active"}
    p = tmp_path / "e.yaml"; p.write_text(yaml.safe_dump(base))
    assert load_engagement(str(p)).stealth == "off"
    p.write_text(yaml.safe_dump({**base, "stealth": "paranoid"}))
    assert load_engagement(str(p)).stealth == "paranoid"
    p.write_text(yaml.safe_dump({**base, "stealth": "bogus"}))
    try:
        load_engagement(str(p)); assert False, "expected EngagementError"
    except EngagementError:
        pass


def test_strength_defaults_normal_and_validates(tmp_path):
    import yaml
    from grin.engagement import load_engagement, EngagementError
    base = {"id": "s", "name": "s", "mode": "adhoc", "scope": {"in": ["t"]},
            "roe": {"allowed_actions": ["passive"]}, "autonomy": "autonomous",
            "env": {"kind": "local"}, "audit_log": str(tmp_path / "a.jsonl"), "state": "active"}
    p = tmp_path / "e.yaml"; p.write_text(yaml.safe_dump(base))
    assert load_engagement(str(p)).strength == "normal"
    p.write_text(yaml.safe_dump({**base, "strength": "max"}))
    assert load_engagement(str(p)).strength == "max"
    p.write_text(yaml.safe_dump({**base, "strength": "bogus"}))
    try:
        load_engagement(str(p)); assert False, "expected EngagementError"
    except EngagementError:
        pass


def test_assess_defaults_false_and_loads_true():
    # SP2: opt-in assessment behavioral flag; default False so every existing engagement is CTF
    assert validate_engagement(VALID).assess is False
    assert validate_engagement({**VALID, "assess": True}).assess is True
