"""Scope matching for engagement targets. Lifted from the Sensei labs.py allowlist
matcher (exact host/IP, *.domain, CIDR, host:port, URL-host) and extended with an
explicit exclude list that overrides the include list. Fail-closed throughout."""
import ipaddress
from urllib.parse import urlparse


def _matches(target: str, entry: str) -> bool:
    if entry == target:
        return True
    if entry.startswith("*."):
        suffix = entry[1:]  # ".acme.test"
        return target.endswith(suffix) and len(target) > len(suffix)
    if "/" in entry:  # CIDR range
        try:
            return ipaddress.ip_address(target) in ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return False
    return False


def _looks_like_path_only(target: str) -> bool:
    # a CIDR ("10.0.0.0/24") has a numeric tail after '/'; don't treat it as host/path
    tail = target.rsplit("/", 1)[-1]
    return tail.isdigit()


def _identifiers(target: str) -> list[str]:
    """The forms of a target to match: the raw target, plus (for a URL or host/path
    or bare host:port) its host[:port] and bare host/IP."""
    ids = [target]
    host_port = ""
    if "://" in target:
        host_port = urlparse(target).netloc
    elif "/" in target and not _looks_like_path_only(target):
        host_port = target.split("/", 1)[0]
    else:
        host_port = target  # bare host, bare host:port, or CIDR (handled by _matches)
    if host_port and host_port != target:
        ids.append(host_port)
    # always add the bare host (strip port if present)
    if ":" in host_port:
        bare = host_port.rsplit(":", 1)[0]
        if bare and bare not in ids:
            ids.append(bare)
    return ids


def _matches_any(target: str, entries) -> bool:
    return any(_matches(ident, entry)
               for ident in _identifiers(target) for entry in (entries or []))


# IPv4 or IPv4/CIDR tokens embedded anywhere in a command string.
_HOST_TOKEN_RE = __import__("re").compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b")


def command_out_of_scope(command: str, include, exclude) -> list:
    """IP/CIDR tokens in `command` that are NOT in scope. A command may name a host the action's
    `target` field doesn't (e.g. `nmap -sn 192.168.1.0/24` while target=one host) — the spine checks
    the target, so this catches hosts smuggled into the command. Loopback/0.0.0.0 are ignored.
    Returns the offending tokens (empty = the command stays within scope)."""
    bad = []
    for tok in _HOST_TOKEN_RE.findall(command or ""):
        if tok.startswith("127.") or tok.startswith("0.0.0.0"):
            continue
        if not in_scope(tok, include, exclude) and tok not in bad:
            bad.append(tok)
    return bad


def in_scope(target: str, include, exclude) -> bool:
    """True only if target matches an include entry AND no exclude entry.
    Fail-closed: empty target or empty include authorizes nothing; exclude overrides."""
    if not target:
        return False
    if _matches_any(target, exclude):
        return False
    return _matches_any(target, include)
