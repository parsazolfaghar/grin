import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt6.QtWidgets import QApplication
from grin.app.qt_app import ToolStrip


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def test_toolstrip_renders_and_fires(app):
    allowed, denied = [], []
    strip = ToolStrip(on_allow=lambda t: allowed.append(t), on_deny=lambda t: denied.append(t))
    strip.set_tools(["sqlmap", "nikto"])
    assert strip.tool_count() == 2
    strip.allow_first()
    assert allowed == ["sqlmap"]
    strip.set_tools([])
    assert strip.tool_count() == 0
