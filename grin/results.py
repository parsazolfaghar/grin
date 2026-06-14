"""Full tool-output store — the evidence the audit log only fingerprints. Append-only JSONL
keyed by id; the resumed Executor reads an approved action's full output from here, and the
SP4 report will draw evidence from it. Path derived from the engagement."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def results_path(engagement) -> str:
    base, _ext = os.path.splitext(engagement.audit_log)
    return base + ".results.jsonl"


class ResultStore:
    def __init__(self, path: str):
        self._path = Path(path)

    def put(self, *, id: str, command: str, output: str, exit_code) -> None:
        rec = {"id": id, "ts": datetime.now(timezone.utc).isoformat(),
               "command": command, "output": output, "exit_code": exit_code}
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "a") as f:
            f.write(json.dumps(rec) + "\n")

    def get(self, id: str):
        """Return the LATEST record for id, or None."""
        if not self._path.exists():
            return None
        found = None
        for line in self._path.read_text().splitlines():
            rec = json.loads(line)
            if rec.get("id") == id:
                found = rec
        return found
