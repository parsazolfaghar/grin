"""`Grin Setup` entry point. A clicked bundle has no console -> log to ~/.grin/setup.log. Resolves the
bundled Grin payload (added via --add-data as grin_payload) and the OS install dir, then runs the wizard."""
import os
import sys


def _logger():
    import datetime
    path = os.path.expanduser("~/.grin/setup.log")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except OSError:
        pass

    def log(msg):
        try:
            with open(path, "a") as fh:
                fh.write(f"{datetime.datetime.now().isoformat(timespec='seconds')} {msg}\n")
        except OSError:
            pass
    return log


def _payload_dir():
    base = getattr(sys, "_MEIPASS", os.path.abspath("."))
    return os.path.join(base, "grin_payload")


def _install_dest(os_name):
    if os_name == "macos":
        return "/Applications"
    if os_name == "windows":
        return os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "Programs", "Grin")
    return os.path.join(os.path.expanduser("~"), ".local", "bin")


def main(argv=None) -> int:
    log = _logger(); log("setup start")
    try:
        argv = argv if argv is not None else sys.argv[1:]
        argv = [a for a in argv if not a.startswith("-psn_") and not a.startswith("-NS")]
        from PyQt6.QtWidgets import QApplication
        from grin.setup.controller import SetupController
        from grin.setup.wizard import build_wizard
        app = QApplication.instance() or QApplication([])
        c = SetupController()
        payload = _payload_dir()
        children = [os.path.join(payload, x) for x in os.listdir(payload)] if os.path.isdir(payload) else []
        c.grin_src = children[0] if children else ""
        c.grin_dest = _install_dest(c.os_name)
        wiz = build_wizard(c)
        wiz.show()
        return app.exec()
    except BaseException as e:  # noqa: BLE001
        import traceback
        log("FATAL: " + "".join(traceback.format_exception(type(e), e, e.__traceback__)))
        raise


if __name__ == "__main__":
    sys.exit(main())
