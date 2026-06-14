"""The loot store — organizes captured secrets into a per-engagement folder. Writes a structured
secrets.jsonl (full records + provenance) and a human-readable, labeled secrets.md. Full values,
no redaction (proof of exposure); local only."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def loot_dir(engagement) -> str:
    base, _ext = os.path.splitext(engagement.audit_log)
    return base + ".loot"


def _secure(path, mode):
    """Restrict perms (R3): loot holds plaintext secrets — owner-only. Best-effort (POSIX)."""
    try:
        os.chmod(path, mode)
    except OSError:
        pass


class LootStore:
    def __init__(self, directory: str):
        self._dir = Path(directory)

    def record(self, secret, *, objective: str, ts: str | None = None) -> None:
        rec = {
            "label": secret.label, "value": secret.value, "target": secret.target,
            "tool": secret.tool, "command": secret.command, "context": secret.context,
            "objective": objective, "ts": ts or datetime.now(timezone.utc).isoformat(),
        }
        self._dir.mkdir(parents=True, exist_ok=True)
        _secure(self._dir, 0o700)               # owner-only loot dir (R3)
        jp = self._dir / "secrets.jsonl"
        with open(jp, "a") as f:
            f.write(json.dumps(rec) + "\n")
        _secure(jp, 0o600)                       # owner-only secrets file (R3)
        self._render_md(self._load())

    def all(self) -> list:
        return self._load()

    def _load(self) -> list:
        p = self._dir / "secrets.jsonl"
        if not p.exists():
            return []
        return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]

    def _render_md(self, rows) -> None:
        out = ["# Loot — captured secrets", "",
               f"{len(rows)} secret(s). Full values; handle as sensitive.", ""]
        for r in rows:
            out.append(f"## [{r['label']}] {r['target']}")
            out.append(f"- value: {r['value']}")
            out.append(f"- tool: {r['tool']}        command: {r['command']}")
            out.append(f"- objective: {r['objective']}")
            out.append(f"- obtained: {r['ts']}")
            if r.get("context"):
                out.append(f"- context: {r['context']}")
            out.append("")
        mp = self._dir / "secrets.md"
        mp.write_text("\n".join(out))
        _secure(mp, 0o600)                       # owner-only readable loot (R3)
