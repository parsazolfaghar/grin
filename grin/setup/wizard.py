"""Branded PyQt6 setup wizard. Pages call a SetupController (injected) so the logic is testable; the
window reuses the app's phosphor theme + smiley. build_wizard(controller) -> GrinSetupWizard."""
import os

from PyQt6.QtWidgets import (QWizard, QWizardPage, QVBoxLayout, QLabel, QLineEdit, QPushButton,
                             QHBoxLayout)
from PyQt6.QtGui import QPixmap
from PyQt6.QtCore import Qt

_APP = os.path.join(os.path.dirname(os.path.dirname(__file__)), "app")


def _style(widget):
    qss = os.path.join(_APP, "style.qss")
    if os.path.exists(qss):
        with open(qss) as fh:
            widget.setStyleSheet(fh.read())


class GrinSetupWizard(QWizard):
    def __init__(self, controller):
        super().__init__()
        self.c = controller
        self._api_key = ""
        self.setWindowTitle("Grin Setup")
        _style(self)
        self.addPage(self._welcome())
        self.addPage(self._brain())
        self.addPage(self._docker())
        self.addPage(self._install())
        self.addPage(self._finish())

    def _welcome(self):
        p = QWizardPage(); p.setTitle("Welcome to Grin")
        lay = QVBoxLayout(p)
        logo = QLabel()
        pm = QPixmap(os.path.join(_APP, "assets", "logo.png"))
        if not pm.isNull():
            logo.setPixmap(pm.scaled(120, 120, Qt.AspectRatioMode.KeepAspectRatio,
                                     Qt.TransformationMode.SmoothTransformation))
        lay.addWidget(logo, 0, Qt.AlignmentFlag.AlignHCenter)
        lay.addWidget(QLabel("This will set up Grin on your machine."))
        return p

    def _brain(self):
        p = QWizardPage(); p.setTitle("Brain — API Key")
        lay = QVBoxLayout(p)
        lay.addWidget(QLabel("Paste your DeepSeek API key (or leave blank for local Ollama):"))
        self._key_field = QLineEdit(); self._key_field.setPlaceholderText("sk-...")
        self._key_field.textChanged.connect(lambda t: setattr(self, "_api_key", t))
        lay.addWidget(self._key_field)
        save = QPushButton("Save key"); save.clicked.connect(self.commit_key)
        lay.addWidget(save)
        return p

    def _docker(self):
        p = QWizardPage(); p.setTitle("Docker + Arsenal")
        lay = QVBoxLayout(p)
        self._docker_lbl = QLabel("")
        row = QHBoxLayout()
        chk = QPushButton("Check Docker"); chk.clicked.connect(self._on_check_docker)
        ins = QPushButton("Install Docker"); ins.clicked.connect(self._on_install_docker)
        ars = QPushButton("Provision arsenal"); ars.clicked.connect(self._on_arsenal)
        for b in (chk, ins, ars):
            row.addWidget(b)
        lay.addLayout(row); lay.addWidget(self._docker_lbl)
        return p

    def _install(self):
        p = QWizardPage(); p.setTitle("Install Grin")
        lay = QVBoxLayout(p)
        self._install_lbl = QLabel("")
        b = QPushButton("Install Grin to Applications"); b.clicked.connect(self._on_install_grin)
        lay.addWidget(b); lay.addWidget(self._install_lbl)
        return p

    def _finish(self):
        p = QWizardPage(); p.setTitle("Done")
        lay = QVBoxLayout(p); lay.addWidget(QLabel("Grin is set up. Launch it from your apps."))
        return p

    def set_api_key(self, key):
        self._api_key = key

    def commit_key(self):
        if self._api_key:
            self.c.save_key(self._api_key)

    def _on_check_docker(self):
        s = self.c.docker_status()
        self._docker_lbl.setText(f"Docker installed={s['installed']} running={s['running']}")

    def _on_install_docker(self):
        out = self.c.install_docker()
        self._docker_lbl.setText(out.get("note") or out.get("status", ""))

    def _on_arsenal(self):
        self._docker_lbl.setText(f"arsenal: {self.c.provision_arsenal().get('status')}")

    def _on_install_grin(self):
        out = self.c.install_grin(src=getattr(self.c, "grin_src", ""),
                                  dest=getattr(self.c, "grin_dest", ""))
        self._install_lbl.setText(f"Installed to {out.get('installed_to','')}")


def build_wizard(controller) -> GrinSetupWizard:
    return GrinSetupWizard(controller)
