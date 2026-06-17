"""Ensure common tool-install dirs are on PATH. A GUI app launched from Finder/Explorer inherits a
minimal PATH that misses Homebrew (/opt/homebrew/bin, /usr/local/bin) and the sbin dirs, so
shutil.which can't find nmap/sqlmap/etc. and host_has_arsenal wrongly resolves away from local tools.
Prepend the standard dirs that actually exist (no duplicates) so detection + execution work from a
clicked app. Pure + injectable for tests."""
import os

_CANDIDATES = ("/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin", "/usr/local/sbin",
               "/usr/sbin", "/sbin")


def ensure_tool_path(environ=None, exists=os.path.isdir) -> list:
    """Prepend existing tool dirs to environ['PATH'] (in place). Returns the dirs added."""
    environ = environ if environ is not None else os.environ
    cur = environ.get("PATH", "")
    parts = cur.split(os.pathsep) if cur else []
    added = [d for d in _CANDIDATES if exists(d) and d not in parts]
    if added:
        environ["PATH"] = os.pathsep.join(added + parts)
    return added
