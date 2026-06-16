import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt6.QtWidgets import QApplication
from grin.app.qt_app import CheckpointBar


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def test_checkpoint_bar_shows_and_fires(app):
    fired = []
    bar = CheckpointBar(on_decision=lambda d: fired.append(d))
    bar.set_checkpoint({"flag": "GRIN{a}", "target": "t1"})
    assert bar.is_active() is True
    assert "GRIN{a}" in bar.text()
    bar.choose("focus")
    assert fired == ["focus"]
    bar.clear()
    assert bar.is_active() is False
