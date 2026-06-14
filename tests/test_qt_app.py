"""Smoke tests for the native Qt window — skipped where PyQt6 isn't installed. Run headless
under the offscreen QPA platform; assert the window builds and that the action affordances
route through GrinApi (no new execution path lives in the UI)."""
import os

import pytest

pytest.importorskip("PyQt6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from grin.app.qt_app import build_app  # noqa: E402


class FakeApi:
    def __init__(self):
        self.approved, self.denied = [], []

    def doctor(self, *a, **k):
        return {"platform": {"os": "linux", "pkg_mgr": "apt"}, "ok": True,
                "checks": [{"name": "spine online", "status": "ok", "detail": "loaded"}]}

    def list_engagements(self):
        return [{"valid": True, "file": "e.yaml", "id": "eng-1", "mode": "client",
                 "name": "net", "state": "active", "targets": 2, "autonomy": "action-gated"}]

    def findings(self, f):
        return [{"title": "sqli", "target": "t", "severity": "high", "evidence": "e", "tool": "sqlmap"}]

    def audit(self, f):
        return [{"ts": "2026-06-13T20:00:00Z", "decision": "allow",
                 "action_class": "active-scan", "command": "nmap"}]

    def blocked(self, f):
        return [{"id": "p1", "tool": "sqlmap", "command": "-u x", "resolved_class": "exploit",
                 "target": "t"}]

    def approve(self, f, pid):
        self.approved.append(pid); return {"status": "executed", "reason": ""}

    def deny(self, f, pid):
        self.denied.append(pid); return {"status": "denied", "reason": ""}

    def set_backend(self, tool_env):
        self.tool_env = tool_env


@pytest.fixture
def win():
    api = FakeApi()
    _app, w = build_app(api)
    yield w, api
    w.deleteLater()


def test_window_builds_on_boot(win):
    w, _ = win
    assert w.stack.currentWidget() is w.boot


def test_open_engagement_switches_to_live(win):
    w, _ = win
    w.open_engagement("e.yaml")
    assert w.stack.currentWidget() is w.live


def test_blocked_shows_approve_bar(win):
    w, _ = win
    w.open_engagement("e.yaml")
    assert not w.live.approve_bar.isHidden()
    assert w.live._pending == "p1"


def test_approve_routes_through_api(win):
    w, api = win
    w.open_engagement("e.yaml")
    w.live._emit_approve()
    assert api.approved == ["p1"]


def test_deny_routes_through_api(win):
    w, api = win
    w.open_engagement("e.yaml")
    w.live._emit_deny()
    assert api.denied == ["p1"]


def test_mode_toggle_switches_persists_and_rewires(tmp_path, monkeypatch):
    import os
    from grin.app import config
    from grin.app.qt_app import build_app
    cfgp = str(tmp_path / "app.json")
    monkeypatch.setattr(config, "config_path", lambda: cfgp)
    monkeypatch.delenv("GRIN_OLLAMA_URL", raising=False)

    api = FakeApi()
    _app, w = build_app(api)
    assert "LOCAL" in w.chrome.mode_btn.text()          # starts local
    w._toggle_mode()
    assert "SPLIT" in w.chrome.mode_btn.text()          # toggled
    assert config.get_active()[0] == "split"            # persisted
    assert "your-rig" in os.environ["GRIN_OLLAMA_URL"]   # inference rewired to rig
    assert api.tool_env["kind"] == "ssh"                # tools rewired to rig
    w.deleteLater()
