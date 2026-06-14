"""GRIN native desktop window (PyQt6) — frameless, custom chrome, the locked terminal
aesthetic. The UI layer only: it reads/acts through GrinApi (grin/app/api.py), which is the
sole bridge to the engine. No new execution path lives here — start/approve/deny call the
same spine/orchestrator the CLI does.

Construction is import-safe and works under the offscreen QPA platform, so it can be smoke-
tested and screenshot-verified headlessly.
"""
import os

from PyQt6.QtCore import Qt, QTimer, QSettings, QObject, pyqtSignal
from PyQt6.QtGui import (QFontDatabase, QFont, QPixmap, QPainter, QColor, QRadialGradient, QIcon)
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QFrame, QVBoxLayout, QHBoxLayout,
    QGridLayout, QScrollArea, QSizePolicy, QGraphicsDropShadowEffect, QSizeGrip,
)

HERE = os.path.dirname(__file__)
ASSETS = os.path.join(HERE, "assets")
FONTS = os.path.join(HERE, "fonts")
BLUE = "#0b18e8"


# ---------------------------------------------------------------- helpers
def _track(label: QLabel, px: float) -> QLabel:
    """Apply uppercase letter-spacing (QSS can't); returns the label for chaining."""
    f = label.font()
    f.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, px)
    label.setFont(f)
    return label


def _role(w, role: str):
    w.setProperty("role", role)
    return w


def _glow(w, color: str, blur: int = 16):
    eff = QGraphicsDropShadowEffect(w)
    eff.setBlurRadius(blur)
    eff.setColor(QColor(color))
    eff.setOffset(0, 0)
    w.setGraphicsEffect(eff)
    return w


def _marker(kind: str = "") -> QFrame:
    m = QFrame()
    m.setFixedSize(8, 8)
    if kind == "run":
        m.setStyleSheet("border:1px solid #f3df33; background:#f3df33;")
    elif kind == "block":
        m.setStyleSheet("border:1px solid #f6f6f4; background:#f6f6f4;")
    else:
        m.setStyleSheet("border:1px solid rgba(246,246,244,0.52); background:transparent;")
    return m


def _clear(layout):
    while layout.count():
        item = layout.takeAt(0)
        w = item.widget()
        if w is not None:
            w.setParent(None)      # detach immediately so it stops rendering
            w.deleteLater()


# ---------------------------------------------------------------- scanline overlay
class ScanlineOverlay(QWidget):
    """Light CRT scanlines + corner vignette, painted over the whole window."""

    def __init__(self, parent):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setPen(Qt.PenStyle.NoPen)
        line = QColor(0, 0, 0, 14)
        y = 0
        while y < self.height():
            p.fillRect(0, y, self.width(), 1, line)
            y += 3
        g = QRadialGradient(self.width() * 0.5, self.height() * 0.12,
                            max(self.width(), self.height()) * 0.95)
        g.setColorAt(0.62, QColor(0, 0, 0, 0))
        g.setColorAt(1.0, QColor(0, 0, 0, 66))
        p.fillRect(self.rect(), g)


# ---------------------------------------------------------------- clickable frame
class ClickRow(QFrame):
    clicked = pyqtSignal()

    def mousePressEvent(self, e):
        self.clicked.emit()
        super().mousePressEvent(e)


# ---------------------------------------------------------------- chrome
class Chrome(QWidget):
    """Frameless custom title bar: brand, breadcrumb, chips, window controls. Draggable."""

    mode_toggle = pyqtSignal()

    def __init__(self, window):
        super().__init__()
        self.setObjectName("chrome")
        self._win = window
        self._drag = None
        row = QHBoxLayout(self)
        row.setContentsMargins(14, 10, 12, 10)
        row.setSpacing(12)

        mark = QLabel()
        pm = QPixmap(os.path.join(ASSETS, "logo.png"))
        if not pm.isNull():
            mark.setPixmap(pm.scaled(18, 18, Qt.AspectRatioMode.KeepAspectRatio,
                                     Qt.TransformationMode.SmoothTransformation))
        row.addWidget(mark)
        brand = QLabel("GRIN"); brand.setObjectName("brand"); _track(brand, 1.0)
        row.addWidget(brand)
        self.path = QLabel("▸ ~/engagements"); self.path.setObjectName("path"); _track(self.path, 1.2)
        row.addWidget(self.path)
        row.addStretch(1)

        self.runchip = QLabel("● RUNNING"); self.runchip.setObjectName("runchip")
        _track(self.runchip, 2.0); _glow(self.runchip, "#f3df33", 12); self.runchip.hide()
        row.addWidget(self.runchip)
        for text in ("LOCAL AI", "FAIL-CLOSED"):
            c = QLabel(text); _role(c, "chip"); _track(c, 2.0); row.addWidget(c)

        # deployment-mode toggle (roadmap R4): click to switch Local <-> Split(rig)
        self.mode_btn = QPushButton("MODE: LOCAL"); self.mode_btn.setObjectName("modebtn")
        self.mode_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.mode_btn.clicked.connect(self.mode_toggle.emit)
        _track(self.mode_btn, 1.6); row.addWidget(self.mode_btn)

        for glyph, oid, slot in (("−", "wcmin", window.showMinimized),
                                 ("□", "wcmax", self._toggle_max),
                                 ("✕", "wcclose", window.close)):
            b = QPushButton(glyph); _role(b, "wc"); b.setObjectName(oid)
            b.setCursor(Qt.CursorShape.PointingHandCursor); b.clicked.connect(slot)
            row.addWidget(b)

    def _toggle_max(self):
        self._win.showNormal() if self._win.isMaximized() else self._win.showMaximized()

    def set_breadcrumb(self, text):
        self.path.setText("▸ " + text)

    def set_running(self, on, label="● RUNNING"):
        self.runchip.setText(label); self.runchip.setVisible(bool(on))

    def set_mode_label(self, text):
        self.mode_btn.setText(f"MODE: {text}")

    # drag the frameless window from the title bar
    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._drag = e.globalPosition().toPoint() - self._win.frameGeometry().topLeft()

    def mouseMoveEvent(self, e):
        if self._drag is not None and e.buttons() & Qt.MouseButton.LeftButton:
            self._win.move(e.globalPosition().toPoint() - self._drag)

    def mouseReleaseEvent(self, _):
        self._drag = None


# ---------------------------------------------------------------- status bar
class StatusBar(QWidget):
    """Powerline status bar, updated in place. segments: (text, role); 'acc' = yellow cap,
    'stretch' = flexible gap."""

    def __init__(self):
        super().__init__()
        self.setObjectName("status")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._h = QHBoxLayout(self); self._h.setContentsMargins(0, 0, 0, 0); self._h.setSpacing(0)

    def set(self, segments):
        while self._h.count():
            it = self._h.takeAt(0); w = it.widget()
            if w is not None:
                w.setParent(None); w.deleteLater()
        for text, role in segments:
            if role == "stretch":
                self._h.addStretch(1); continue
            seg = QLabel(text); _track(seg, 1.6)
            seg.setObjectName("segacc") if role == "acc" else _role(seg, role or "seg")
            seg.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
            self._h.addWidget(seg)


# ---------------------------------------------------------------- boot view
class BootView(QWidget):
    open_engagement = pyqtSignal(str)   # emits the engagement file path

    def __init__(self):
        super().__init__()
        outer = QVBoxLayout(self); outer.setContentsMargins(0, 0, 0, 0); outer.setSpacing(0)

        # hero
        hero = QWidget()
        hg = QHBoxLayout(hero); hg.setContentsMargins(28, 30, 28, 18); hg.setSpacing(34)
        mascot = QLabel()
        pm = QPixmap(os.path.join(ASSETS, "logo.png"))
        if not pm.isNull():
            mascot.setPixmap(pm.scaled(164, 164, Qt.AspectRatioMode.KeepAspectRatio,
                                       Qt.TransformationMode.SmoothTransformation))
        mascot.setFixedWidth(164)
        hg.addWidget(mascot, 0, Qt.AlignmentFlag.AlignVCenter)

        col = QVBoxLayout(); col.setSpacing(0)
        word = QLabel("GRIN"); word.setObjectName("wordmark"); _glow(word, "#f6f6f4", 18)
        col.addWidget(word)
        rule = QFrame(); rule.setObjectName("rule"); rule.setFixedHeight(1)
        col.addSpacing(16); col.addWidget(rule); col.addSpacing(12)
        sub = QLabel("AUTONOMOUS RED-TEAM ORCHESTRATOR\nLOCAL AI · ANY AUTHORIZED TARGET")
        sub.setObjectName("sub"); _track(sub, 3.0); col.addWidget(sub)
        spec = QLabel("SPINE  FAIL-CLOSED        ARSENAL  KALI · BLACKARCH")
        spec.setObjectName("spec"); _track(spec, 2.0); col.addSpacing(14); col.addWidget(spec)
        col.addStretch(1)
        hg.addLayout(col, 1)
        outer.addWidget(hero)

        # preflight log
        self.log = QVBoxLayout(); self.log.setContentsMargins(28, 2, 28, 16); self.log.setSpacing(6)
        logw = QWidget(); logw.setLayout(self.log); outer.addWidget(logw)

        sec = QLabel("[ ENGAGEMENTS ]"); _role(sec, "sec"); _track(sec, 3.0)
        sec.setContentsMargins(28, 6, 28, 4); outer.addWidget(sec)

        self.elist = QVBoxLayout(); self.elist.setContentsMargins(22, 4, 22, 14); self.elist.setSpacing(0)
        elw = QWidget(); elw.setLayout(self.elist); outer.addWidget(elw)
        outer.addStretch(1)
        self._rows = []   # [(file, ClickRow)] for valid engagements
        self._sel = -1    # keyboard selection index

    def set_data(self, doctor: dict, engagements: list):
        self.set_engagements(engagements)
        self.set_doctor(doctor)

    def set_doctor_pending(self):
        _clear(self.log)
        lab = QLabel("[ .. ]  PREFLIGHT — CHECKING…"); _role(lab, "log"); _track(lab, 1.0)
        self.log.addWidget(lab)

    def set_doctor(self, doctor: dict):
        _clear(self.log)
        checks = (doctor or {}).get("checks", [])
        if not checks:
            lab = QLabel("[ .. ] preflight unavailable".upper()); _role(lab, "log"); _track(lab, 1.0)
            self.log.addWidget(lab)
        for c in checks[:5]:
            ok = c.get("status") == "ok"
            lab = QLabel(f"[ {'OK' if ok else c.get('status','?').upper()} ]  "
                         f"{c.get('name','')} — {c.get('detail','')}".upper())
            _role(lab, "logok" if ok else "log"); _track(lab, 1.0)
            self.log.addWidget(lab)
        ready = QLabel("[ READY ]  AWAITING ENGAGEMENT"); _role(ready, "ready")
        _track(ready, 1.0); _glow(ready, "#f3df33", 12); self.log.addWidget(ready)

    def set_engagements(self, engagements: list):
        _clear(self.elist)
        self._rows = []
        if not engagements:
            empty = QLabel("NO ENGAGEMENTS IN THIS FOLDER"); _role(empty, "esub")
            _track(empty, 1.5); empty.setContentsMargins(6, 8, 0, 0); self.elist.addWidget(empty)
            self._sel = -1
            return
        for e in engagements:
            row = self._erow(e)
            self.elist.addWidget(row)
            if e.get("valid", True):
                self._rows.append((e.get("file") or "", row))
        self._sel = 0 if self._rows else -1
        self._highlight()

    def _erow(self, e: dict) -> QWidget:
        row = ClickRow()
        _role(row, "erow")
        row.setCursor(Qt.CursorShape.PointingHandCursor)
        h = QHBoxLayout(row); h.setContentsMargins(6, 11, 6, 11); h.setSpacing(12)
        if e.get("valid", True):
            h.addWidget(_marker(""), 0, Qt.AlignmentFlag.AlignTop)
            col = QVBoxLayout(); col.setSpacing(4)
            t = QLabel(f"{e.get('id','?')} · {e.get('mode','')}".upper())
            _role(t, "etitle"); _track(t, 0.6); col.addWidget(t)
            s = QLabel(f"{e.get('name','')} // {e.get('state','')} // "
                       f"{e.get('targets',0)} TARGET(S)".upper())
            _role(s, "esub"); _track(s, 1.0); col.addWidget(s)
            h.addLayout(col, 1)
            go = QLabel("OPEN ▸"); _role(go, "ego")
            _track(go, 1.6); h.addWidget(go, 0, Qt.AlignmentFlag.AlignVCenter)
            row.clicked.connect(lambda f=e.get("file"): self._click_row(f or ""))
        else:
            col = QVBoxLayout(); col.setSpacing(4)
            t = QLabel(f"INVALID · {os.path.basename(e.get('file',''))}".upper())
            _role(t, "etitle"); col.addWidget(t)
            s = QLabel(str(e.get("error", "")).upper()); _role(s, "esub"); col.addWidget(s)
            h.addLayout(col, 1)
        return row

    # ---- keyboard selection ----
    def _highlight(self):
        for i, (_f, row) in enumerate(self._rows):
            row.setObjectName("erowhot" if i == self._sel else "")
            row.style().unpolish(row); row.style().polish(row)

    def move_selection(self, delta: int):
        if not self._rows:
            return
        self._sel = max(0, min(len(self._rows) - 1, self._sel + delta))
        self._highlight()

    def _click_row(self, file: str):
        for i, (f, _r) in enumerate(self._rows):
            if f == file:
                self._sel = i
                break
        self._highlight()
        self.open_engagement.emit(file)

    def open_selected(self):
        if 0 <= self._sel < len(self._rows):
            self.open_engagement.emit(self._rows[self._sel][0])


# ---------------------------------------------------------------- live view
class LiveView(QWidget):
    approve = pyqtSignal(str)   # pending id
    deny = pyqtSignal(str)
    copied = pyqtSignal(str)    # text copied to clipboard (for status feedback)

    def __init__(self):
        super().__init__()
        self._pending = None
        outer = QVBoxLayout(self); outer.setContentsMargins(0, 0, 0, 0); outer.setSpacing(0)

        prow = QWidget(); prow.setObjectName("promptrow")
        ph = QHBoxLayout(prow); ph.setContentsMargins(16, 14, 16, 14); ph.setSpacing(8)
        ps = QLabel("PS grin>"); ps.setObjectName("ps")
        self.cmd = QLabel(""); self.cmd.setObjectName("cmd")
        ph.addWidget(ps); ph.addWidget(self.cmd, 1)
        outer.addWidget(prow)

        # approve bar
        self.approve_bar = QWidget(); self.approve_bar.setObjectName("approve")
        ah = QHBoxLayout(self.approve_bar); ah.setContentsMargins(16, 12, 16, 12); ah.setSpacing(14)
        atag = QLabel("AWAITING APPROVAL"); atag.setObjectName("atag"); _track(atag, 2.0)
        _glow(atag, "#f3df33", 10)
        self.acmd = QLabel(""); self.acmd.setObjectName("acmd")
        ah.addWidget(atag); ah.addWidget(self.acmd, 1)
        ka = QLabel("A"); ka.setObjectName("kbdy"); kah = QLabel("approve"); _role(kah, "khint")
        kd = QLabel("D"); _role(kd, "kbd"); kdh = QLabel("deny"); _role(kdh, "khint")
        ka.mousePressEvent = lambda _e: self._emit_approve()
        kd.mousePressEvent = lambda _e: self._emit_deny()
        for w in (ka, kah, kd, kdh):
            ah.addWidget(w)
        self.approve_bar.hide()
        outer.addWidget(self.approve_bar)

        # three-pane grid (hairline gaps)
        grid = QWidget(); grid.setObjectName("grid")
        gl = QHBoxLayout(grid); gl.setContentsMargins(0, 0, 0, 0); gl.setSpacing(1)
        self.obj_box, oc = self._cell("[ OBJECTIVES ]")
        self.find_box, fc = self._cell("[ FINDINGS ]")
        self.audit_box, ac = self._cell("[ AUDIT ]", rev="JSONL")
        gl.addWidget(oc, 105); gl.addWidget(fc, 125); gl.addWidget(ac, 92)
        outer.addWidget(grid, 1)
        self._objrev = self.obj_box.rev; self._findrev = self.find_box.rev

    def _cell(self, title, rev=""):
        cell = QWidget(); _role(cell, "cell")
        v = QVBoxLayout(cell); v.setContentsMargins(15, 14, 15, 12); v.setSpacing(0)
        head = QHBoxLayout()
        lbl = QLabel(title); _role(lbl, "celllbl"); _track(lbl, 2.6)
        rv = QLabel(rev); _role(rv, "cellrev"); _track(rv, 1.0)
        head.addWidget(lbl); head.addStretch(1); head.addWidget(rv)
        v.addLayout(head); v.addSpacing(10)
        body = QVBoxLayout(); body.setSpacing(0); body.setContentsMargins(0, 0, 0, 0)
        bw = QWidget(); bw.setLayout(body); bw.setStyleSheet("background: transparent;")
        sa = QScrollArea(); sa.setWidgetResizable(True); sa.setWidget(bw)
        sa.setFrameShape(QFrame.Shape.NoFrame)
        sa.viewport().setStyleSheet("background: transparent;")
        sa.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        v.addWidget(sa, 1)
        # lightweight handle exposing the body layout + the count label
        class _Box:
            pass
        box = _Box(); box.body = body; box.rev = rv
        return box, cell

    def set_data(self, snap: dict):
        snap = snap or {}
        objectives = snap.get("objectives", []) or []
        findings = snap.get("findings", []) or []
        audit = snap.get("audit", []) or []
        blocked = snap.get("blocked", []) or []

        self._objrev.setText(str(len(objectives)))
        self._findrev.setText(str(len(findings)))

        _clear(self.obj_box.body)
        for o in objectives:
            st = (o.get("status") or "").lower()
            mk = "run" if st == "running" else ("block" if st == "blocked" else "")
            sub = o.get("detail", "") or st
            self.obj_box.body.addWidget(self._prow(_marker(mk),
                                                   f"{o.get('objective','')} · {o.get('target','')}",
                                                   sub, suby=(st == "blocked")))
        self.obj_box.body.addStretch(1)

        _clear(self.find_box.body)
        for f in findings:
            self.find_box.body.addWidget(self._frow(f))
        self.find_box.body.addStretch(1)

        _clear(self.audit_box.body)
        for a in audit:
            cls = "auditrefuse" if a.get("decision") == "refuse" else (
                "auditallow" if a.get("decision") == "allow" else "auditline")
            ts = (a.get("ts", "") or "")[11:19]
            text = f"{ts}  {a.get('decision','')} {a.get('action_class','')} {a.get('command','')}".strip()
            ln = QLabel(text.upper()); _role(ln, cls); _track(ln, 0.6); ln.setWordWrap(True)
            ln.setCursor(Qt.CursorShape.PointingHandCursor)
            ln.mousePressEvent = lambda _e, c=a.get("command", ""): self._copy(c)
            self.audit_box.body.addWidget(ln)
        self.audit_box.body.addStretch(1)

        if blocked:
            b = blocked[0]
            self._pending = b.get("id")
            self.acmd.setText(f"{b.get('tool','')}: {b.get('command','')}   "
                              f"// {b.get('resolved_class','')} // {b.get('target','')}")
            self.approve_bar.show()
        else:
            self._pending = None
            self.approve_bar.hide()

    def _prow(self, marker, title, sub, suby=False):
        row = QFrame(); _role(row, "prow")
        h = QHBoxLayout(row); h.setContentsMargins(0, 9, 0, 9); h.setSpacing(11)
        h.addWidget(marker, 0, Qt.AlignmentFlag.AlignTop)
        col = QVBoxLayout(); col.setSpacing(4)
        t = QLabel(str(title).upper()); _role(t, "ptitle"); _track(t, 0.5); t.setWordWrap(True)
        s = QLabel(str(sub).upper()); _role(s, "psuby" if suby else "psub"); _track(s, 0.8); s.setWordWrap(True)
        col.addWidget(t); col.addWidget(s); h.addLayout(col, 1)
        return row

    def _copy(self, text):
        if not text:
            return
        QApplication.clipboard().setText(str(text))
        self.copied.emit(str(text))

    def _frow(self, f):
        row = QFrame(); _role(row, "prow")
        row.setCursor(Qt.CursorShape.PointingHandCursor)
        cmd = f.get("command") or f.get("evidence") or f.get("title", "")
        row.mousePressEvent = lambda _e, c=cmd: self._copy(c)
        h = QHBoxLayout(row); h.setContentsMargins(0, 9, 0, 9); h.setSpacing(11)
        sev = (f.get("severity") or "info").lower()
        role = {"critical": "sevhigh", "high": "sevhigh", "medium": "sevmed",
                "med": "sevmed"}.get(sev, "sevinfo")
        chip = QLabel(sev.upper()); _role(chip, role); _track(chip, 1.4)
        h.addWidget(chip, 0, Qt.AlignmentFlag.AlignTop)
        col = QVBoxLayout(); col.setSpacing(4)
        t = QLabel(f"{f.get('title','')} · {f.get('target','')}".upper())
        _role(t, "ptitle"); _track(t, 0.5); t.setWordWrap(True)
        s = QLabel(f"{f.get('evidence','')} // {f.get('tool','')}".upper())
        _role(s, "psub"); _track(s, 0.8); s.setWordWrap(True)
        col.addWidget(t); col.addWidget(s); h.addLayout(col, 1)
        return row

    def set_command(self, text):
        self.cmd.setText(text)

    def _emit_approve(self):
        if self._pending:
            self.approve.emit(self._pending)

    def _emit_deny(self):
        if self._pending:
            self.deny.emit(self._pending)


def desktop_notify(title: str, body: str) -> None:
    """Best-effort LOCAL desktop notification (macOS osascript / Linux notify-send). Fail-soft.
    The phone version is roadmap R7."""
    import shutil
    import subprocess
    import sys
    try:
        if sys.platform == "darwin":
            subprocess.run(["osascript", "-e",
                            f"display notification {body!r} with title {title!r}"],
                           capture_output=True, timeout=5)
        elif shutil.which("notify-send"):
            subprocess.run(["notify-send", title, body], capture_output=True, timeout=5)
    except Exception:  # noqa: BLE001
        pass


class _Async(QObject):
    """Carries a worker-thread result back to the GUI thread via a queued signal."""
    done = pyqtSignal(object)


def _snap_sig(snap):
    """A cheap signature of a live snapshot — used to skip pane rebuilds when nothing changed."""
    snap = snap or {}
    objs = tuple((o.get("objective"), o.get("target"), o.get("status"))
                 for o in snap.get("objectives", []) or [])
    finds = tuple((f.get("title"), f.get("severity")) for f in snap.get("findings", []) or [])
    audit = tuple((a.get("ts"), a.get("command")) for a in snap.get("audit", []) or [])
    blocked = tuple(b.get("id") for b in snap.get("blocked", []) or [])
    return (snap.get("status"), objs, finds, audit, blocked)


# ---------------------------------------------------------------- main window
class GrinWindow(QWidget):
    def __init__(self, api, notify_fn=desktop_notify):
        super().__init__()
        self.api = api
        self._notify = notify_fn
        self._job_id = None
        self._job_file = None
        self._last_sig = None             # last rendered live-snapshot signature (skip rebuilds)
        self._notified_pending = set()   # pending ids already pushed (notify once)
        self._notified_done = False
        self.setObjectName("root")
        self.setWindowTitle("GRIN")
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)   # so keyPressEvent fires
        geo = QSettings("grin", "app").value("geometry")
        if geo is not None:
            self.restoreGeometry(geo)                     # remember size/position
        else:
            self.resize(1040, 820)                        # sensible default
            scr = QApplication.primaryScreen()
            if scr is not None:                           # center on screen on first launch
                c = scr.availableGeometry().center()
                self.move(c.x() - self.width() // 2, c.y() - self.height() // 2)

        root = QVBoxLayout(self); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)
        self.chrome = Chrome(self); root.addWidget(self.chrome)

        self.boot = BootView(); self.boot.open_engagement.connect(self.open_engagement)
        self.live = LiveView()
        self.live.approve.connect(self._approve); self.live.deny.connect(self._deny)
        self.live.copied.connect(self._on_copied)

        from PyQt6.QtWidgets import QStackedWidget
        self.stack = QStackedWidget()
        self.stack.addWidget(self.boot); self.stack.addWidget(self.live)
        root.addWidget(self.stack, 1)

        self.keymap = QLabel("[↑/↓] select   [enter] open   [esc] back   [a]/[d] approve / deny   "
                             "[r] refresh   [?] keys   ·   click a finding/audit line to copy")
        self.keymap.setObjectName("keymap"); _track(self.keymap, 1.2); self.keymap.hide()
        root.addWidget(self.keymap)

        self.status = StatusBar()
        self.status.set([("MODE: IDLE", "seg"), ("ENGAGEMENTS: 0", "segdim"),
                         ("", "stretch"), ("FAIL-CLOSED", "acc")])
        root.addWidget(self.status)

        self.overlay = ScanlineOverlay(self); self.overlay.resize(self.size())
        self._grip = QSizeGrip(self)   # drag bottom-right to resize the frameless window
        self._grip.resize(16, 16)

        self._poll = QTimer(self); self._poll.setInterval(1500); self._poll.timeout.connect(self._tick)

        self.chrome.mode_toggle.connect(self._toggle_mode)
        self._apply_active_profile()   # set endpoint + tool env from the persisted profile
        self.refresh_boot()

    # ---- keyboard nav + QoL ----
    def keyPressEvent(self, e):
        t = e.text().lower()
        key = e.key()
        if t == "?":
            self.keymap.setVisible(not self.keymap.isVisible()); return
        if self.stack.currentWidget() is self.boot:
            if key == Qt.Key.Key_Down or t == "j":
                self.boot.move_selection(1)
            elif key == Qt.Key.Key_Up or t == "k":
                self.boot.move_selection(-1)
            elif key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                self.boot.open_selected()
            elif t == "r":
                self.refresh_boot()
            else:
                super().keyPressEvent(e)
        else:   # live
            if key == Qt.Key.Key_Escape:
                self.refresh_boot()                # back to the boot console
            elif t == "a":
                self.live._emit_approve()
            elif t == "d":
                self.live._emit_deny()
            elif t == "r" and self._job_id:
                self._tick()
            else:
                super().keyPressEvent(e)

    def _on_copied(self, text):
        short = (text[:48] + "…") if len(text) > 48 else text
        seg = self.status
        # transient feedback in the status bar
        seg.set([("COPIED", "segy"), (short, "segdim"), ("", "stretch"), ("FAIL-CLOSED", "acc")])

    def closeEvent(self, e):
        QSettings("grin", "app").setValue("geometry", self.saveGeometry())
        super().closeEvent(e)

    # ---- deployment mode (roadmap R4) ----
    def _apply_active_profile(self):
        from grin.app import config
        name, profile = config.get_active()
        env = config.apply_profile(profile)          # sets $GRIN_OLLAMA_URL
        self.api.set_backend(env)                    # rebuild Ollama client + tool-env override
        self.chrome.set_mode_label(profile.get("label", name.upper()))

    def _toggle_mode(self):
        from grin.app import config
        name, _ = config.get_active()
        config.set_active(config.next_profile(name))
        self._apply_active_profile()
        self.refresh_boot()                          # re-check doctor at the new endpoint

    def resizeEvent(self, e):
        self.overlay.resize(self.size()); self.overlay.raise_()
        self._grip.move(self.width() - self._grip.width(), self.height() - self._grip.height())
        self._grip.raise_()   # above the scanline overlay so it stays draggable
        super().resizeEvent(e)

    def _async(self, fn, on_done):
        """Run fn() on a worker thread; deliver its result to on_done on the GUI thread (Qt
        queues the signal across threads). Keeps the UI responsive during blocking calls (e.g. the
        doctor's Ollama HTTP checks). Fail-soft: exceptions come back as {'error': ...}."""
        import threading
        carrier = _Async()
        carrier.done.connect(on_done)
        self._async_keep = carrier   # keep a ref so it isn't GC'd before delivery

        def work():
            try:
                res = fn()
            except Exception as e:  # noqa: BLE001
                res = {"error": str(e)}
            carrier.done.emit(res)
        threading.Thread(target=work, daemon=True).start()

    # ---- boot ----
    def refresh_boot(self):
        # render engagements + chrome immediately (fast), then fill the preflight log off-thread
        engagements = self.api.list_engagements()
        self.boot.set_engagements(engagements)
        self.boot.set_doctor_pending()
        self.status.set([("MODE: IDLE", "seg"),
                         (f"ENGAGEMENTS: {len(engagements)}", "segdim"),
                         ("", "stretch"), ("FAIL-CLOSED", "acc")])
        self.chrome.set_breadcrumb("~/engagements"); self.chrome.set_running(False)
        self.stack.setCurrentWidget(self.boot)
        self._async(self.api.doctor, self.boot.set_doctor)   # doctor off the UI thread

    # ---- live ----
    def open_engagement(self, file):
        if not file:
            return
        self._job_file = file
        self._last_sig = None   # force a render on (re)entry
        snap = {"objectives": [], "findings": self.api.findings(file),
                "audit": self.api.audit(file), "blocked": self.api.blocked(file)}
        self._show_live(file, snap, running=False)
        self._last_sig = _snap_sig(snap)

    def _show_live(self, file, snap, running):
        try:
            rows = {e.get("file"): e for e in self.api.list_engagements()}
            e = rows.get(file, {})
            crumb = f"{e.get('id','engagement')} · {e.get('mode','')} · {e.get('autonomy','')}".upper()
        except Exception:  # noqa: BLE001
            crumb = os.path.basename(file)
        self.chrome.set_breadcrumb(crumb)
        self.chrome.set_running(running)
        self.live.set_data(snap)
        self.status.set([("MODE: RUNNING" if running else "MODE: ACTION-GATED", "seg"),
                         (f"OBJ {len(snap.get('objectives',[]))}", "seg"),
                         (f"FIND {len(snap.get('findings',[]))}", "segy"),
                         (f"BLOCKED {len(snap.get('blocked',[]))}", "seg"),
                         ("", "stretch"), ("SPINE: FAIL-CLOSED", "segdim")])
        self.stack.setCurrentWidget(self.live)

    def start(self, file, goal):
        res = self.api.start_engagement(file, goal)
        if res.get("error"):
            return res
        self._job_id = res.get("job_id"); self._job_file = file
        self._last_sig = None   # force the first live render
        self._notified_pending = set(); self._notified_done = False
        self.live.set_command(f'engage --goal "{goal}"')
        self._poll.start()
        return res

    def _tick(self):
        if not self._job_id:
            return
        snap = self.api.engagement_state(self._job_id)
        if snap.get("error"):
            return
        running = snap.get("status") == "running"
        sig = _snap_sig(snap)
        if sig != self._last_sig:              # only rebuild panes when something changed
            self._show_live(self._job_file, snap, running=running)
            self._last_sig = sig
        self._notify_transitions(snap, running)
        if not running:
            self._poll.stop()

    def _notify_transitions(self, snap, running):
        """Desktop-notify on a NEW gated action or on completion (once each). Never blocks."""
        for b in snap.get("blocked", []) or []:
            pid = b.get("id")
            if pid and pid not in self._notified_pending:
                self._notified_pending.add(pid)
                self._notify("GRIN — approval needed",
                             f"{b.get('tool', '')} {b.get('command', '')} // {b.get('target', '')}")
        if not running and not self._notified_done:
            self._notified_done = True
            self._notify("GRIN — engagement finished", f"status: {snap.get('status', 'done')}")

    def _approve(self, pid):
        if self._job_file:
            self.api.approve(self._job_file, pid); self._tick_or_reopen()

    def _deny(self, pid):
        if self._job_file:
            self.api.deny(self._job_file, pid); self._tick_or_reopen()

    def _tick_or_reopen(self):
        if self._job_id:
            self._tick()
        else:
            self.open_engagement(self._job_file)


# ---------------------------------------------------------------- bootstrap
def build_app(api, argv=None):
    """Create (or reuse) the QApplication, load fonts + QSS, return (app, window)."""
    app = QApplication.instance() or QApplication(argv or [])
    for ttf in ("JetBrainsMono-Regular.ttf", "JetBrainsMono-Bold.ttf",
                "JetBrainsMono-ExtraBold.ttf", "ArchivoBlack-Regular.ttf"):
        QFontDatabase.addApplicationFont(os.path.join(FONTS, ttf))
    app.setFont(QFont("JetBrains Mono", 10))
    _ic = os.path.join(ASSETS, "icon.png")           # rounded app-style icon (fallback to raw logo)
    icon = QIcon(_ic if os.path.exists(_ic) else os.path.join(ASSETS, "logo.png"))
    if not icon.isNull():
        app.setWindowIcon(icon)
    qss = os.path.join(HERE, "style.qss")
    if os.path.exists(qss):
        with open(qss) as f:
            app.setStyleSheet(f.read())
    win = GrinWindow(api)
    win.setWindowIcon(icon)
    return app, win


def run(engagements_dir="."):
    from grin.app.api import GrinApi
    app, win = build_app(GrinApi(engagements_dir=engagements_dir))
    win.show()
    return app.exec()
