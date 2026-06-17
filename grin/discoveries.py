"""Deterministic discovery summary — aggregate what tools actually found, independent of the LLM's
findings. `discover()` is pure (never raises); `gather_records()` does the IO of collecting tool
output from where the engine persists it: the per-task JOURNALS (the autonomous `engage` path —
this is where the Executor records full output) AND the results store (the gate/resume path)."""
import glob
import json
import os
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
            # prefer an explicit target (journal step carries action.target), else parse the command
            target = (rec or {}).get("target") or target_from_command(command)
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


def gather_records(engagement) -> list:
    """IO: collect executed-step records {command, output, target} for an engagement from BOTH the
    results store (gate/resume path) and the per-task journals (autonomous `engage` path — where the
    Executor writes full tool output). Never raises; returns [] when there is nothing yet."""
    recs = []
    try:
        from grin.results import ResultStore, results_path
        recs.extend(ResultStore(results_path(engagement)).all())
    except Exception:  # noqa: BLE001
        pass
    try:
        base, _ext = os.path.splitext(engagement.audit_log)
        for path in sorted(glob.glob(f"{base}.*.journal.json")):
            try:
                data = json.loads(open(path).read())
            except (OSError, json.JSONDecodeError):
                continue
            for i, step in enumerate(data.get("steps", []) or []):
                if step.get("decision") != "executed":
                    continue
                action = step.get("action") or {}
                recs.append({"id": f"{os.path.basename(path)}#{i}",
                             "command": action.get("command", ""),
                             "output": step.get("output", ""),
                             "target": action.get("target", ""),
                             "exit_code": step.get("exit_code")})
    except Exception:  # noqa: BLE001
        pass
    return recs


def summary_line(d: Discoveries) -> str:
    def _n(n, w):
        return f"{n} {w}" + ("" if n == 1 else "s")
    return " · ".join([_n(d.commands_run, "cmd"), _n(len(d.hosts), "host"),
                       _n(len(d.credentials), "cred"), _n(len(d.flags), "flag")])
