"""Deterministic discovery summary — aggregate what tools actually found from the persisted
results store, independent of the LLM's findings. Pure, never raises (house rule, see
grin/services.py + grin/extractors.py)."""
import re
from dataclasses import dataclass, field

from grin.services import extract_services
from grin.extractors import extract

# first IPv4, else URL host, else a dotted/hostname token, else "" — best-effort target attribution
_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_URL_HOST = re.compile(r"https?://([^/\s:]+)")
_SCHEME_HOST = re.compile(r"(?:ssh|ftp|http|https|smb)://([^/\s:]+)", re.IGNORECASE)
_HOSTish = re.compile(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9-]+)+)\b")


def target_from_command(command: str) -> str:
    c = command or ""
    m = _IPV4.search(c)
    if m:
        return m.group(1)
    m = _URL_HOST.search(c) or _SCHEME_HOST.search(c)
    if m:
        return m.group(1)
    m = _HOSTish.search(c)
    return m.group(1) if m else ""


def _tool_from_command(command: str) -> str:
    c = (command or "").strip()
    return c.split()[0] if c else ""


@dataclass(frozen=True)
class HostServices:
    target: str
    services: list = field(default_factory=list)


@dataclass(frozen=True)
class Discoveries:
    hosts: list = field(default_factory=list)
    credentials: list = field(default_factory=list)
    flags: list = field(default_factory=list)
    commands_run: int = 0


def discover(records) -> Discoveries:
    try:
        recs = list(records or [])
        by_target = {}        # target -> {port: Service}
        order = []            # preserve first-seen target order
        creds, flags = [], []
        seen_secret = set()
        commands_run = 0
        for rec in recs:
            output = (rec or {}).get("output") or ""
            command = (rec or {}).get("command") or ""
            if not output:
                continue
            commands_run += 1
            target = target_from_command(command)
            for svc in extract_services(output):
                bucket = by_target.setdefault(target, {})
                if target not in order:
                    order.append(target)
                bucket.setdefault(svc.port, svc)
            tool = _tool_from_command(command)
            for sec in extract(tool, command, output, target):
                key = (sec.label, sec.value)
                if key in seen_secret:
                    continue
                seen_secret.add(key)
                (flags if sec.label == "flag" else creds).append(sec)
        hosts = [HostServices(target=t,
                              services=sorted(by_target[t].values(), key=lambda s: s.port))
                 for t in sorted(order)]
        return Discoveries(hosts=hosts, credentials=creds, flags=flags,
                           commands_run=commands_run)
    except Exception:  # noqa: BLE001 - deterministic extractor: never raise
        return Discoveries()


def summary_line(d: Discoveries) -> str:
    def _n(n, w):
        return f"{n} {w}" + ("" if n == 1 else "s")
    return " · ".join([_n(d.commands_run, "cmd"), _n(len(d.hosts), "host"),
                       _n(len(d.credentials), "cred"), _n(len(d.flags), "flag")])
