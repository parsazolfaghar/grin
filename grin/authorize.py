"""authorize(): scope ∩ ¬exclude ∩ ROE-class ∩ window ∩ active. Fail-closed —
the gate decision (run vs pending) is a separate stage (see gate.py)."""
from dataclasses import dataclass
from datetime import datetime

from grin.engagement import Engagement
from grin.scope import in_scope


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""


def _in_any_window(now: datetime, windows) -> bool:
    if not windows:          # empty = anytime
        return True
    return any(w.start <= now <= w.end for w in windows)


def authorize(target: str, resolved_class: str, engagement: Engagement,
              now: datetime) -> Decision:
    if engagement.state != "active":
        return Decision(False, f"engagement state is {engagement.state!r}, not active")
    if not in_scope(target, engagement.scope.include, engagement.scope.exclude):
        return Decision(False, f"target {target!r} is out of scope")
    if resolved_class not in engagement.roe.allowed_actions:
        return Decision(False, f"action class {resolved_class!r} not in ROE allowed_actions")
    if not _in_any_window(now, engagement.roe.windows):
        return Decision(False, "current time is outside all ROE windows")
    return Decision(True, "")
