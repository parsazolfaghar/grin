import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt6.QtWidgets import QApplication
from grin.app.qt_app import build_app


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class FakeApi:
    def __init__(self, pending=None):
        self.engagements_dir = "."
        self._pending = pending or []
    # toggles / boot
    def set_backend(self, env): pass
    def set_stealth(self, l): pass
    def set_strength(self, l): pass
    def set_tool_acquire(self, l): pass
    def interpret(self, t): return {"targets": [], "can_engage": False, "manual": {"sections": []}}
    def list_engagements(self): return []
    def doctor(self, *a, **k): return {"checks": [], "ok": True}
    # live view
    def findings(self, f): return []
    def audit(self, f): return []
    def blocked(self, f): return []
    # tool acquire
    def pending_tools(self, f): return list(self._pending)
    def engage_text(self, t): return {"job_id": "j1", "started": True, "file": "/tmp/e.yaml"}


def test_open_engagement_populates_tool_strip_immediately(app):
    api = FakeApi(pending=["sqlmap"])
    _a, w = build_app(api)
    w.open_engagement("/tmp/e.yaml")
    assert w.tool_strip.tool_count() == 1      # shown right away, not on next tick
    w.deleteLater()


def test_engage_text_binds_job_file(app):
    api = FakeApi(pending=[])
    _a, w = build_app(api)
    w._engage_text("www.test.com")
    assert w._job_file == "/tmp/e.yaml"        # ad-hoc run is bound -> tool prompts can surface
    w._poll.stop()                             # don't leak the live-poll timer into later tests
    w.deleteLater()
