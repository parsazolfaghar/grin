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
        self.tool_acquire = "ask"
    def set_tool_acquire(self, level): self.tool_acquire = level
    def set_strength(self, level): pass
    def set_stealth(self, level): pass
    def set_backend(self, env): pass
    def interpret(self, text): return {"targets": [], "can_engage": False, "manual": {"sections": []}}
    def list_engagements(self): return []
    def doctor(self, *a, **k): return {"checks": [], "ok": True}


def test_tools_toggle_cycles_and_sets_api(app):
    api = FakeApi()
    _a, w = build_app(api)
    assert "ASK" in w.chrome.tools_btn.text()
    w._toggle_tools()
    assert "AUTO" in w.chrome.tools_btn.text()
    assert api.tool_acquire == "auto"
    w._toggle_tools()
    assert "NEVER" in w.chrome.tools_btn.text()
    assert api.tool_acquire == "never"
    w._toggle_tools()
    assert "ASK" in w.chrome.tools_btn.text()
    assert api.tool_acquire == "ask"
    w.deleteLater()
