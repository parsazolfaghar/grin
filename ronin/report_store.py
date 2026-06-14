"""Persist + reload the SP3 EngagementResult so `ronin report` can run separately from
`ronin engage`. JSON next to the audit log. Rebuilds Finding/Objective objects on load."""
import json
import os
from dataclasses import asdict
from pathlib import Path

from ronin.finding import Finding
from ronin.objective import Objective
from ronin.orchestrator import EngagementResult


def result_path(engagement) -> str:
    base, _ext = os.path.splitext(engagement.audit_log)
    return base + ".engagement.json"


def _obj_to_dict(o: Objective) -> dict:
    return {"objective": o.objective, "target": o.target}


def _planlog_entry_to_dict(e: dict) -> dict:
    d = dict(e)
    if "objectives" in d:
        d["objectives"] = [_obj_to_dict(o) for o in d["objectives"]]
    return d


def save_result(path: str, result: EngagementResult) -> None:
    data = {
        "status": result.status,
        "findings": [asdict(f) for f in result.findings],
        "objectives_run": [_obj_to_dict(o) for o in result.objectives_run],
        "paused": [{"objective": _obj_to_dict(p["objective"]),
                    "pending_id": p.get("pending_id"), "journal": p.get("journal")}
                   for p in result.paused],
        "plan_log": [_planlog_entry_to_dict(e) for e in result.plan_log],
    }
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2))


def _obj_from_dict(d: dict) -> Objective:
    return Objective(objective=d["objective"], target=d["target"])


def _planlog_entry_from_dict(d: dict) -> dict:
    e = dict(d)
    if "objectives" in e:
        e["objectives"] = [_obj_from_dict(o) for o in e["objectives"]]
    return e


def load_result(path: str) -> EngagementResult:
    data = json.loads(Path(path).read_text())   # FileNotFoundError if absent
    return EngagementResult(
        status=data["status"],
        findings=[Finding(**f) for f in data.get("findings", [])],
        objectives_run=[_obj_from_dict(o) for o in data.get("objectives_run", [])],
        paused=[{"objective": _obj_from_dict(p["objective"]),
                 "pending_id": p.get("pending_id"), "journal": p.get("journal")}
                for p in data.get("paused", [])],
        plan_log=[_planlog_entry_from_dict(e) for e in data.get("plan_log", [])],
    )
