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
        self.strength = "normal"
    def set_strength(self, level): self.strength = level
    def set_stealth(self, level): pass
    def set_backend(self, env): pass
    def interpret(self, text): return {"targets": [], "can_engage": False, "manual": {"sections": []}}
    def list_engagements(self): return []
    def doctor(self, *a, **k): return {"checks": [], "ok": True}


def test_strength_toggle_cycles_and_sets_api(app):
    api = FakeApi()
    _a, w = build_app(api)
    assert "NORMAL" in w.chrome.strength_btn.text()
    w._toggle_strength()
    assert "AGGRESSIVE" in w.chrome.strength_btn.text()
    assert api.strength == "aggressive"
    w._toggle_strength()
    assert "MAX" in w.chrome.strength_btn.text()
    assert api.strength == "max"
    w._toggle_strength()
    assert "RECON" in w.chrome.strength_btn.text()
    assert api.strength == "recon"
    w._toggle_strength()
    assert "NORMAL" in w.chrome.strength_btn.text()
    assert api.strength == "normal"
    w.deleteLater()
