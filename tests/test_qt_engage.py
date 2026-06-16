import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt6.QtWidgets import QApplication

from grin.app.qt_app import EngageBar


@pytest.fixture(scope="module")
def qtbot_or_app():
    app = QApplication.instance() or QApplication([])
    yield app


class FakeApi:
    def __init__(self):
        self.engaged = None
        self.engagements_dir = "."
    def interpret(self, text):
        if "test.com" in text:
            return {"goal": "bypass login", "targets": ["www.test.com"],
                    "target_type": "web-url", "bare_target": False, "can_engage": True,
                    "allowed_actions": ["passive", "active-scan", "exploit"],
                    "manual": {"header": "Web target.", "sections": [
                        {"tactic": "reconnaissance", "items": ["Active Scanning [nmap]"]}]}}
        return {"goal": text, "targets": [], "target_type": "unknown",
                "bare_target": False, "can_engage": False, "allowed_actions": [],
                "manual": {"header": "", "sections": []}}
    def engage_text(self, text):
        self.engaged = text
        return {"job_id": "j1", "started": True}


def test_engage_bar_preview_and_enable(qtbot_or_app):
    api = FakeApi()
    fired = []
    bar = EngageBar(api, on_engage=lambda text: fired.append(text))
    bar.set_text("bypass login page for www.test.com")
    bar.refresh_preview()
    assert "www.test.com" in bar.preview_text()
    assert bar.engage_enabled() is True
    bar.set_text("blah")
    bar.refresh_preview()
    assert bar.engage_enabled() is False


def test_engage_bar_fires_callback(qtbot_or_app):
    api = FakeApi()
    fired = []
    bar = EngageBar(api, on_engage=lambda text: fired.append(text))
    bar.set_text("www.test.com")
    bar.refresh_preview()
    bar._do_engage()
    assert fired == ["www.test.com"]
