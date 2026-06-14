"""`grin app` — open the native window over the engine. pywebview is imported lazily so the
engine, CLI, and tests never need it; a clear hint is printed if the [app] extra is missing."""
import os
import sys

from grin.app.api import GrinApi


def web_dir() -> str:
    return os.path.join(os.path.dirname(__file__), "web")


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    engagements_dir = argv[0] if argv else "."
    try:
        import webview
    except ImportError:
        print("grin app needs pywebview — install it with:  pip install 'grin[app]'",
              file=sys.stderr)
        return 1
    api = GrinApi(engagements_dir=engagements_dir)
    index = os.path.join(web_dir(), "index.html")
    webview.create_window("GRIN", url=index, js_api=api, width=1180, height=820,
                          background_color="#0b18e8")
    webview.start()
    return 0
