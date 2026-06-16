"""`grin app` — open the native PyQt6 window over the engine. PyQt6 is imported lazily (via
qt_app) so the engine, CLI, and tests never need it; a clear hint is printed if the [app]
extra is missing."""
import sys


def main(argv=None) -> int:
    from grin.config import load_env_file
    load_env_file()
    argv = argv if argv is not None else sys.argv[1:]
    engagements_dir = argv[0] if argv else "."
    try:
        from grin.app.qt_app import run
    except ImportError:
        print("grin app needs PyQt6 — install it with:  pip install 'grin[app]'",
              file=sys.stderr)
        return 1
    return run(engagements_dir=engagements_dir)
