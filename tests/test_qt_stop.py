import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt6.QtWidgets import QApplication
from grin.app.qt_app import build_app


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class FakeApi:
    def __init__(self):
        self.engagements_dir = "."
        self.stopped = None
    def stop_engagement(self, job_id): self.stopped = job_id; return {"status": "stopping"}
    def set_strength(self, l): pass
    def set_stealth(self, l): pass
    def set_tool_acquire(self, l): pass
    def set_backend(self, env): pass
    def interpret(self, t): return {"targets": [], "can_engage": False, "manual": {"sections": []}}
    def list_engagements(self): return []
    def doctor(self, *a, **k): return {"checks": [], "ok": True}


def test_stop_button_visible_when_running_and_calls_api(app):
    api = FakeApi()
    _a, w = build_app(api)
    assert w.chrome.stop_btn.isHidden() is True          # hidden when idle
    w.chrome.set_running(True)
    assert w.chrome.stop_btn.isHidden() is False         # shown while running
    w._job_id = "j1"
    w._stop_engagement()
    assert api.stopped == "j1"
    w.deleteLater()
