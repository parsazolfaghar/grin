"""Per-engagement working state: the pending (gated) action queue + the set of
approved phases for phase-gated mode. JSON-backed so `ronin run` and `ronin gate`
(separate processes) share it. This is mutable state — distinct from the append-only
audit log."""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


class PendingStore:
    def __init__(self, path: str):
        self._path = Path(path)

    def _load(self) -> dict:
        if not self._path.exists():
            return {"pending": [], "approved_phases": []}
        data = json.loads(self._path.read_text() or "{}")
        data.setdefault("pending", [])
        data.setdefault("approved_phases", [])
        return data

    def _save(self, data: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(data, indent=2))

    def add(self, *, target: str, tool: str, command: str, resolved_class: str) -> str:
        data = self._load()
        pid = uuid.uuid4().hex[:8]
        data["pending"].append({
            "id": pid,
            "ts": datetime.now(timezone.utc).isoformat(),
            "target": target, "tool": tool, "command": command,
            "resolved_class": resolved_class,
        })
        self._save(data)
        return pid

    def list(self) -> list:
        return self._load()["pending"]

    def pop(self, pid: str):
        data = self._load()
        for i, e in enumerate(data["pending"]):
            if e["id"] == pid:
                entry = data["pending"].pop(i)
                self._save(data)
                return entry
        return None

    def approve_phase(self, action_class: str) -> None:
        data = self._load()
        if action_class not in data["approved_phases"]:
            data["approved_phases"].append(action_class)
            self._save(data)

    def approved_phases(self) -> set:
        return set(self._load()["approved_phases"])
