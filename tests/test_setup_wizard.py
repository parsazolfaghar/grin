import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt6.QtWidgets import QApplication
from grin.setup.wizard import build_wizard


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class FakeController:
    os_name = "macos"
    def __init__(self): self.calls = []
    def save_key(self, key, **k): self.calls.append(("save_key", key))
    def docker_status(self): self.calls.append(("docker_status",)); return {"installed": True, "running": True}
    def install_docker(self): self.calls.append(("install_docker",)); return {"status": "installed"}
    def provision_arsenal(self): self.calls.append(("arsenal",)); return {"status": "ok"}
    def install_grin(self, **k): self.calls.append(("install_grin",)); return {"installed_to": "/Applications/Grin.app"}


def test_wizard_builds_with_pages(app):
    c = FakeController()
    wiz = build_wizard(c)
    titles = [wiz.page(i).title() for i in wiz.pageIds()]
    assert any("Welcome" in t for t in titles)
    assert any("Brain" in t or "Key" in t for t in titles)
    assert any("Docker" in t for t in titles)


def test_brain_page_saves_key(app):
    c = FakeController()
    wiz = build_wizard(c)
    wiz.set_api_key("sk-test")
    wiz.commit_key()
    assert ("save_key", "sk-test") in c.calls
