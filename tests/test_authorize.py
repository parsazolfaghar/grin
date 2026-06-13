from datetime import datetime
from ronin.authorize import authorize, Decision
from ronin.engagement import validate_engagement

BASE = {
    "id": "e1", "name": "n", "mode": "client",
    "scope": {"in": ["*.acme.test", "203.0.113.0/24"], "exclude": ["vpn.acme.test"]},
    "roe": {"allowed_actions": ["passive", "active-scan", "exploit"],
            "windows": [{"start": "2026-06-13T18:00", "end": "2026-06-14T06:00"}]},
    "autonomy": "action-gated", "env": {"kind": "local"},
    "audit_log": "./audit/e1.jsonl", "state": "active",
}
IN_WINDOW = datetime(2026, 6, 13, 20, 0)
OUT_WINDOW = datetime(2026, 6, 14, 12, 0)


def eng(**over):
    d = {**BASE, **over}
    return validate_engagement(d)


def test_in_scope_allowed_class_in_window_allows():
    d = authorize("www.acme.test", "active-scan", eng(), IN_WINDOW)
    assert isinstance(d, Decision)
    assert d.allowed is True


def test_out_of_scope_refused():
    d = authorize("evil.example.com", "passive", eng(), IN_WINDOW)
    assert d.allowed is False
    assert "scope" in d.reason.lower()


def test_excluded_target_refused():
    d = authorize("vpn.acme.test", "passive", eng(), IN_WINDOW)
    assert d.allowed is False


def test_disallowed_class_refused():
    d = authorize("www.acme.test", "post-exploit", eng(), IN_WINDOW)
    assert d.allowed is False
    assert "class" in d.reason.lower()


def test_out_of_window_refused():
    d = authorize("www.acme.test", "active-scan", eng(), OUT_WINDOW)
    assert d.allowed is False
    assert "window" in d.reason.lower()


def test_empty_windows_means_anytime():
    e = eng(roe={"allowed_actions": ["passive"], "windows": []})
    d = authorize("www.acme.test", "passive", e, OUT_WINDOW)
    assert d.allowed is True


def test_paused_engagement_refuses_everything():
    e = eng(state="paused")
    d = authorize("www.acme.test", "passive", e, IN_WINDOW)
    assert d.allowed is False
    assert "active" in d.reason.lower()


def test_done_engagement_refuses_everything():
    d = authorize("www.acme.test", "passive", eng(state="done"), IN_WINDOW)
    assert d.allowed is False


def test_empty_target_refused():
    d = authorize("", "passive", eng(), IN_WINDOW)
    assert d.allowed is False
