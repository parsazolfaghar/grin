"""Per-engagement tool-acquisition requests: tools an engagement needs that aren't in the arsenal,
awaiting the operator's Allow/Deny in the app. JSON-backed (mirrors PendingStore); mutable working
state, distinct from the append-only audit log. Never raises on a missing/garbled file."""
import json
import os
from pathlib import Path


def tool_requests_path(engagement) -> str:
    """Where an engagement's tool-requests live — next to its audit log, <id>.tools.json."""
    base, _ = os.path.splitext(engagement.audit_log)
    return base + ".tools.json"


class ToolRequestStore:
    def __init__(self, path: str):
        self._path = Path(path)

    def _load(self) -> dict:
        try:
            data = json.loads(self._path.read_text() or "{}")
        except (OSError, json.JSONDecodeError):
            return {"requested": [], "resolved": [], "denied": []}
        for k in ("requested", "resolved", "denied"):
            data.setdefault(k, [])
        return data

    def _save(self, data: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(data, indent=2))

    def request(self, tool: str) -> None:
        data = self._load()
        if tool in data["requested"] or tool in data["resolved"] or tool in data["denied"]:
            return
        data["requested"].append(tool)
        self._save(data)

    def requested(self) -> list:
        return list(self._load()["requested"])

    def _move(self, tool: str, to: str) -> None:
        data = self._load()
        if tool in data["requested"]:
            data["requested"].remove(tool)
        if tool not in data[to]:
            data[to].append(tool)
        self._save(data)

    def resolve(self, tool: str) -> None:
        self._move(tool, "resolved")

    def deny(self, tool: str) -> None:
        self._move(tool, "denied")

    def is_resolved(self, tool: str) -> bool:
        return tool in self._load()["resolved"]

    def is_denied(self, tool: str) -> bool:
        return tool in self._load()["denied"]
