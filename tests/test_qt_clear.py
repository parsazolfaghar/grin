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
        self.cleared = 0
    def clear_engagements(self): self.cleared += 1; return {"cleared": 0}
    def set_strength(self, l): pass
    def set_stealth(self, l): pass
    def set_tool_acquire(self, l): pass
    def set_backend(self, env): pass
    def interpret(self, t): return {"targets": [], "can_engage": False, "manual": {"sections": []}}
    def list_engagements(self): return []
    def doctor(self, *a, **k): return {"checks": [], "ok": True}


def test_clear_button_calls_api(app):
    api = FakeApi()
    _a, w = build_app(api)
    assert w.boot.clear_btn is not None
    w._clear_engagements()
    assert api.cleared == 1
    w.deleteLater()
