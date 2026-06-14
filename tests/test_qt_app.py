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


def test_boot_keyboard_selection_and_open(win):
    w, _ = win
    opened = []
    w.boot.open_engagement.connect(opened.append)
    w.boot.set_data({"checks": []}, [
        {"valid": True, "file": "a.yaml", "id": "a", "mode": "client", "name": "n", "state": "active", "targets": 1},
        {"valid": True, "file": "b.yaml", "id": "b", "mode": "own-lab", "name": "m", "state": "active", "targets": 1}])
    assert w.boot._sel == 0
    w.boot.move_selection(1); assert w.boot._sel == 1
    w.boot.move_selection(5); assert w.boot._sel == 1            # clamped at last
    w.boot.open_selected(); assert opened == ["b.yaml"]


def test_esc_returns_to_boot(win):
    from PyQt6.QtGui import QKeyEvent
    from PyQt6.QtCore import QEvent, Qt as _Qt
    w, _ = win
    w.open_engagement("e.yaml")
    assert w.stack.currentWidget() is w.live
    w.keyPressEvent(QKeyEvent(QEvent.Type.KeyPress, _Qt.Key.Key_Escape, _Qt.KeyboardModifier.NoModifier))
    assert w.stack.currentWidget() is w.boot


def test_copy_emits_signal(win):
    w, _ = win
    got = []
    w.live.copied.connect(got.append)
    w.live._copy("nmap -sV 203.0.113.7")
    assert got == ["nmap -sV 203.0.113.7"]


def test_notify_transitions_fire_once(win):
    w, _ = win
    calls = []
    w._notify = lambda title, body: calls.append((title, body))
    snap = {"status": "running", "blocked": [{"id": "p1", "tool": "sqlmap", "command": "-u x", "target": "t"}]}
    w._notify_transitions(snap, running=True)
    w._notify_transitions(snap, running=True)            # same pid -> no repeat
    assert sum(1 for c in calls if "approval" in c[0].lower()) == 1
    w._notify_transitions({"status": "completed", "blocked": []}, running=False)
    assert any("finished" in c[0].lower() for c in calls)


def test_window_icon_is_the_logo(win):
    w, _ = win
    assert not w.windowIcon().isNull()   # app/window icon set to the Grin logo


def test_snap_sig_changes_only_on_real_change():
    from grin.app.qt_app import _snap_sig
    a = {"status": "running", "objectives": [{"objective": "x", "target": "t", "status": "running"}],
         "findings": [], "audit": [], "blocked": []}
    b = dict(a, objectives=[{"objective": "x", "target": "t", "status": "running"}])
    assert _snap_sig(a) == _snap_sig(b)                    # same data -> same sig (skip rebuild)
    c = dict(b, findings=[{"title": "sqli", "severity": "high"}])
    assert _snap_sig(a) != _snap_sig(c)                    # changed -> different sig (rebuild)


def test_refresh_boot_renders_engagements_without_waiting_on_doctor(win):
    w, _ = win
    w.refresh_boot()
    assert len(w.boot._rows) == 1   # engagements painted immediately; doctor runs off-thread


def test_resize_geometry_math():
    from grin.app.qt_app import _resized
    from PyQt6.QtCore import QRect
    geo = QRect(100, 100, 800, 600)
    assert _resized({"right"}, geo, 50, 0).width() == 850            # right edge widens
    g = _resized({"left"}, geo, 30, 0); assert g.left() == 130 and g.width() == 770
    g = _resized({"right", "bottom"}, geo, 40, 20)
    assert g.width() == 840 and g.height() == 620                    # br corner
    g = _resized({"top"}, geo, 0, 25); assert g.top() == 125 and g.height() == 575


def test_window_has_edge_and_corner_handles(win):
    w, _ = win
    assert set(w._handles) == {"top", "bottom", "left", "right",
                               "lefttop", "righttop", "leftbottom", "rightbottom"}
