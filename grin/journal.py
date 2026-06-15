"""The Executor's working memory + resume artifact. The journal is fed back to the model
each turn (render_history) and saved to disk so a paused task can resume. Distinct from the
SP1 audit log (tamper-evident evidence); the journal is mutable agent state."""
import json
import os
from dataclasses import dataclass, asdict
from pathlib import Path

from grin.finding import Finding
from grin.secret import Secret


def journal_path(engagement, task_id: str) -> str:
    base, _ext = os.path.splitext(engagement.audit_log)
    return f"{base}.{task_id}.journal.json"


@dataclass
class Step:
    action: dict                      # {tool, command, target, declared_class, why}
    decision: str                     # executed | refused | pending | parse_miss
    output: str = ""
    exit_code: int | None = None
    reason: str = ""
    pending_id: str | None = None


class Journal:
    def __init__(self, *, task_id: str, objective: str, target: str, engagement_path: str,
                 path: str, max_steps: int = 12):
        self.task_id = task_id
        self.objective = objective
        self.target = target
        self.engagement_path = engagement_path
        self.path = path
        self.max_steps = max_steps
        self.steps: list[Step] = []
        self.findings: list[Finding] = []
        self.secrets: list = []
        self.awaiting_pending_id: str | None = None

    def add_step(self, step: Step) -> None:
        self.steps.append(step)

    def set_findings(self, findings) -> None:
        self.findings = list(findings)

    def set_secrets(self, secrets) -> None:
        self.secrets = list(secrets)

    def update_pending_result(self, pending_id: str, output: str, exit_code) -> None:
        for s in self.steps:
            if s.decision == "pending" and s.pending_id == pending_id:
                s.decision = "executed"
                s.output = output
                s.exit_code = exit_code
        self.awaiting_pending_id = None

    @staticmethod
    def _clip(text: str, head: int = 500, tail: int = 1200) -> str:
        """Show enough tool output for the model to act on. Tool results (e.g. hydra's
        `login: X password: Y` line) often sit at the END after a long banner, so keep both
        the head and the tail rather than a single front slice that hides the result."""
        text = text or ""
        if len(text) <= head + tail:
            return text
        return f"{text[:head]}\n...[{len(text) - head - tail} chars omitted]...\n{text[-tail:]}"

    def render_history(self) -> str:
        if not self.steps:
            return "(no actions taken yet)"
        lines = []
        for s in self.steps:
            cmd = s.action.get("command", "") if isinstance(s.action, dict) else ""
            if s.decision == "executed":
                lines.append(f"- [executed] {cmd} -> {self._clip(s.output)}")
            elif s.decision == "refused":
                lines.append(f"- [refused] {cmd} ({s.reason})")
            elif s.decision == "pending":
                lines.append(f"- [awaiting approval] {cmd}")
            elif s.decision == "no_evidence":
                lines.append("- [rejected: reported findings/secrets with no tool run yet — "
                             "run a tool to gather evidence first]")
            elif s.decision == "duplicate":
                lines.append(f"- [skipped: already ran {cmd} — "
                             "choose a DIFFERENT action or finish]")
            else:
                lines.append("- [unparseable model reply, retried]")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id, "objective": self.objective, "target": self.target,
            "engagement_path": self.engagement_path, "path": self.path,
            "max_steps": self.max_steps, "awaiting_pending_id": self.awaiting_pending_id,
            "steps": [asdict(s) for s in self.steps],
            "findings": [asdict(f) for f in self.findings],
            "secrets": [asdict(s) for s in self.secrets],
        }

    def save(self) -> None:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.path).write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: str) -> "Journal":
        data = json.loads(Path(path).read_text())
        j = cls(task_id=data["task_id"], objective=data["objective"], target=data["target"],
                engagement_path=data["engagement_path"], path=data["path"],
                max_steps=data.get("max_steps", 12))
        j.awaiting_pending_id = data.get("awaiting_pending_id")
        j.steps = [Step(**s) for s in data.get("steps", [])]
        j.findings = [Finding(**f) for f in data.get("findings", [])]
        j.secrets = [Secret(**s) for s in data.get("secrets", [])]
        return j
