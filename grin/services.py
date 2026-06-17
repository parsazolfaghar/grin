"""Deterministic extractor: parse nmap output into discovered open services. Pure, never raises.
Same philosophy as grin/extractors.py -- don't make the weak LLM parse tool output."""
import re
from dataclasses import dataclass

_LINE = re.compile(r"(?im)^\s*(\d+)/tcp\s+open\s+(\S+)")
_REPORT = re.compile(r"(?im)^Nmap scan report for (.+?)\s*$")
_PAREN_IP = re.compile(r"\(([\d.]+)\)")


@dataclass(frozen=True)
class Service:
    port: int
    name: str


def extract_live_hosts(nmap_output: str) -> list:
    """Parse nmap host-discovery output into the list of live hosts (in report order, deduped). A host
    counts as live when its 'Nmap scan report for <host>' block contains 'Host is up'. Prefers the IP
    in 'name (1.2.3.4)' form. Surfaces hosts found by a ping sweep (-sn) or by a port scan where every
    port was filtered — cases extract_services() (open-ports only) correctly returns nothing for."""
    text = nmap_output or ""
    matches = list(_REPORT.finditer(text))
    hosts, seen = [], set()
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = text[m.end():end]
        if "Host is up" not in block:
            continue
        raw = m.group(1).strip()
        pm = _PAREN_IP.search(raw)
        host = pm.group(1) if pm else raw
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)
    return hosts


def extract_services(nmap_output: str) -> list:
    out = []
    seen = set()
    for m in _LINE.finditer(nmap_output or ""):
        port = int(m.group(1))
        name = m.group(2).strip()
        if port in seen:
            continue
        seen.add(port)
        out.append(Service(port=port, name=name))
    return out
