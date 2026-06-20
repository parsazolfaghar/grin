"""`grin app` — open the native PyQt6 window over the engine. PyQt6 is imported lazily (via
qt_app) so the engine, CLI, and tests never need it; a clear hint is printed if the [app]
extra is missing. A clicked .app has no console, so startup + any fatal error is logged to
~/.grin/app.log for diagnosis."""
import sys


def _logger():
    import os
    import datetime
    path = os.path.expanduser(os.environ.get("GRIN_APP_LOG", "~/.grin/app.log"))
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except OSError:
        pass

    def log(msg: str) -> None:
        try:
            with open(path, "a") as fh:
                fh.write(f"{datetime.datetime.now().isoformat(timespec='seconds')} {msg}\n")
        except OSError:
            pass
    return log


def resolve_engagements_dir(argv) -> str:
    """Where the GUI looks for engagements. An explicit arg wins; else $GRIN_ENGAGEMENTS; else the
    first existing of ~/.grin/engagements or ~/grin/examples; else '.'. Lets a Finder/launcher-clicked
    app (cwd '/') still show engagements instead of an empty list."""
    import os
    if argv:
        return argv[0]
    env = os.environ.get("GRIN_ENGAGEMENTS")
    if env:
        return env
    for cand in (os.path.expanduser("~/.grin/engagements"), os.path.expanduser("~/grin/examples")):
        if os.path.isdir(cand):
            return cand
    return "."


def main(argv=None) -> int:
    log = _logger()
    log(f"launch.main start (sys.argv={sys.argv})")
    try:
        from grin.config import load_env_file
        load_env_file()
        try:                          # the Grin Brain ships seeded; make sure it's populated
            from grin.brain import Brain
            Brain().ensure_seeded()
        except Exception as e:  # noqa: BLE001
            log(f"brain seed skipped: {e}")
        from grin.toolpath import ensure_tool_path
        added = ensure_tool_path()   # a Finder-clicked app lacks Homebrew on PATH -> add it
        if added:
            log(f"PATH += {added}")
        from grin.dockerenv import ensure_docker_host
        dh = ensure_docker_host()    # a clicked app has no DOCKER_HOST -> point it at Colima/Docker
        if dh:
            log(f"DOCKER_HOST={dh}")
        argv = argv if argv is not None else sys.argv[1:]
        # ignore macOS process-serial / -NS* launch args so the dir stays sane
        argv = [a for a in argv if not a.startswith("-psn_") and not a.startswith("-NS")]
        engagements_dir = resolve_engagements_dir(argv)
        log(f"engagements_dir={engagements_dir!r}")
        try:
            from grin.app.qt_app import run
        except ImportError as e:
            log(f"PyQt6 import failed: {e}")
            print("grin app needs PyQt6 — install it with:  pip install 'grin[app]'",
                  file=sys.stderr)
            return 1
        log("calling run()")
        rc = run(engagements_dir=engagements_dir)
        log(f"run() returned {rc}")
        return rc
    except BaseException as e:  # noqa: BLE001 - log fatal startup errors (no console in a .app)
        import traceback
        log("FATAL: " + "".join(traceback.format_exception(type(e), e, e.__traceback__)))
        raise


if __name__ == "__main__":   # PyInstaller runs this file as the bundle entry
    sys.exit(main())
