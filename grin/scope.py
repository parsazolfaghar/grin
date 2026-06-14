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


def in_scope(target: str, include, exclude) -> bool:
    """True only if target matches an include entry AND no exclude entry.
    Fail-closed: empty target or empty include authorizes nothing; exclude overrides."""
    if not target:
        return False
    if _matches_any(target, exclude):
        return False
    return _matches_any(target, include)
