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
        self.stealth = "off"
    def set_stealth(self, level): self.stealth = level
    def list_engagements(self): return []
    def doctor(self, *a, **k): return {"checks": [], "ok": True}
    def set_backend(self, env): pass
    def interpret(self, text): return {"can_engage": False}


def test_stealth_toggle_cycles_and_sets_api(app):
    api = FakeApi()
    _a, w = build_app(api)
    assert "OFF" in w.chrome.stealth_btn.text()
    w._toggle_stealth()
    assert "QUIET" in w.chrome.stealth_btn.text()
    assert api.stealth == "quiet"
    w._toggle_stealth()
    assert "PARANOID" in w.chrome.stealth_btn.text()
    assert api.stealth == "paranoid"
    w._toggle_stealth()
    assert "OFF" in w.chrome.stealth_btn.text()
    assert api.stealth == "off"
    w.deleteLater()
