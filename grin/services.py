"""Deterministic extractor: parse nmap output into discovered open services. Pure, never raises.
Same philosophy as grin/extractors.py -- don't make the weak LLM parse tool output."""
import re
from dataclasses import dataclass

_LINE = re.compile(r"(?im)^\s*(\d+)/tcp\s+open\s+(\S+)")


@dataclass(frozen=True)
class Service:
    port: int
    name: str


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
