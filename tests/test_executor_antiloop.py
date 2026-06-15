"""Anti-loop dedup + no-progress termination tests for the Executor.

Three scenarios:
1. A model that always emits the same command executes it exactly once,
   then the loop breaks early via the no-progress counter.
2. Distinct commands are NOT treated as duplicates — each executes.
3. render_history marks duplicate-skipped steps with the expected text.
"""
import json
from datetime import datetime

import pytest

from grin.engagement import validate_engagement
from grin.executor import execute_task, MAX_NOPROGRESS
from grin.inference import FakeClient
from grin.journal import Journal, Step
from grin.runner import FakeRunner, ExecResult

NOW = datetime(2026, 1, 1)


def make_eng(tmp_path, **over):
    d = {
        "id": "e1", "name": "n", "mode": "client",
        "scope": {"in": ["*.acme.test", "203.0.113.0/24"], "exclude": ["vpn.acme.test"]},
        "roe": {"allowed_actions": ["passive", "active-scan", "exploit"], "windows": []},
        "autonomy": "autonomous", "env": {"kind": "local"},
        "audit_log": str(tmp_path / "audit" / "e1.jsonl"), "state": "active",
    }
    d.update(over)
    return validate_engagement(d)


def _action(tool, command, target, cls):
    return json.dumps({"action": {"tool": tool, "command": command, "target": target,
                                  "declared_class": cls, "why": "x"}})


def _done(findings=None):
    return json.dumps({"done": True, "findings": findings or []})


class CountingFakeRunner:
    """FakeRunner that counts how many times each command is actually invoked."""

    def __init__(self, outputs=None):
        self._outputs = outputs or {}
        self.call_counts: dict[str, int] = {}

    def run(self, target: str, command: str, timeout: int = 60) -> ExecResult:
        self.call_counts[command] = self.call_counts.get(command, 0) + 1
        if command in self._outputs:
            return self._outputs[command]
        return ExecResult(output=f"[fake: {command}]", exit_code=0, duration_s=0.0,
                          timed_out=False)


# ---------------------------------------------------------------------------
# Test 1: same command emitted repeatedly — executes once, breaks early
# ---------------------------------------------------------------------------

def test_duplicate_command_executed_once_then_loop_breaks(tmp_path):
    """Model always returns the same nmap command. The command runs exactly once;
    subsequent duplicates are skipped and the no-progress counter breaks the loop
    well before max_steps is reached."""
    eng = make_eng(tmp_path)
    nmap_cmd = "nmap -sV 203.0.113.7"
    # FakeClient sticks on the last reply — always returns the same action
    client = FakeClient(_action("nmap", nmap_cmd, "203.0.113.7", "active-scan"))
    runner = CountingFakeRunner({nmap_cmd: ExecResult("80/tcp open", 0, 0.5, False)})

    max_steps = 20  # large budget so only no-progress breaks the loop
    res = execute_task(eng, objective="find web", target="203.0.113.7",
                       client=client, runner=runner, now=NOW, max_steps=max_steps)

    # Command was run exactly once (all subsequent attempts were deduped)
    assert runner.call_counts.get(nmap_cmd, 0) == 1, (
        f"Expected command to execute exactly once, got {runner.call_counts}"
    )

    # Loop broke early — did not consume the full step budget
    assert len(res.journal.steps) < max_steps, (
        f"Expected early break, got {len(res.journal.steps)} steps (max={max_steps})"
    )

    # Status is budget_exhausted (no-progress break falls through to the same final return)
    assert res.status == "budget_exhausted"

    # The journal contains at least one "duplicate" step
    decisions = [s.decision for s in res.journal.steps]
    assert "duplicate" in decisions, f"Expected a duplicate step, got: {decisions}"

    # The first executed step is "executed"
    assert decisions[0] == "executed"


# ---------------------------------------------------------------------------
# Test 2: distinct commands are not deduplicated — each executes
# ---------------------------------------------------------------------------

def test_distinct_commands_each_execute(tmp_path):
    """Different commands must all execute without being blocked by the dedup set."""
    eng = make_eng(tmp_path)
    target = "203.0.113.7"
    client = FakeClient([
        _action("nmap", "nmap -sV 203.0.113.7", target, "active-scan"),
        _action("hydra", "hydra -l root -P /tmp/pass.txt 203.0.113.7 ssh", target, "exploit"),
        _done([{"title": "SSH weak password", "severity": "high", "evidence": "found: root/toor",
                "tool": "hydra", "command": "hydra -l root ...", "recommendation": "change pw"}]),
    ])
    runner = CountingFakeRunner({
        "nmap -sV 203.0.113.7": ExecResult("22/tcp open ssh", 0, 0.5, False),
        "hydra -l root -P /tmp/pass.txt 203.0.113.7 ssh": ExecResult(
            "[22][ssh] login: root   password: toor", 0, 1.2, False),
    })

    res = execute_task(eng, objective="find creds", target=target,
                       client=client, runner=runner, now=NOW, max_steps=10)

    assert res.status == "completed"
    # Both commands ran exactly once
    assert runner.call_counts.get("nmap -sV 203.0.113.7", 0) == 1
    assert runner.call_counts.get(
        "hydra -l root -P /tmp/pass.txt 203.0.113.7 ssh", 0) == 1

    executed = [s for s in res.journal.steps if s.decision == "executed"]
    assert len(executed) == 2, f"Expected 2 executed steps, got: {[s.decision for s in res.journal.steps]}"


# ---------------------------------------------------------------------------
# Test 3: render_history shows the duplicate-skip marker
# ---------------------------------------------------------------------------

def test_render_history_marks_duplicate(tmp_path):
    """Journal.render_history() must include the duplicate-skip marker text
    for steps recorded with decision='duplicate'."""
    eng = make_eng(tmp_path)
    task_id = "deadbeef"
    from grin.journal import journal_path
    j = Journal(
        task_id=task_id,
        objective="test",
        target="203.0.113.7",
        engagement_path=str(tmp_path / "audit" / "e1.jsonl"),
        path=str(tmp_path / f"e1.{task_id}.journal.json"),
        max_steps=12,
    )

    nmap_cmd = "nmap -sV 203.0.113.7"
    # A real executed step
    j.add_step(Step(
        action={"tool": "nmap", "command": nmap_cmd, "target": "203.0.113.7",
                "declared_class": "active-scan", "why": "scan"},
        decision="executed",
        output="80/tcp open http",
    ))
    # A duplicate step (same command, skipped by dedup)
    j.add_step(Step(
        action={"tool": "nmap", "command": nmap_cmd, "target": "203.0.113.7",
                "declared_class": "active-scan", "why": "x"},
        decision="duplicate",
    ))

    history = j.render_history()

    assert "skipped" in history.lower(), f"Expected 'skipped' in history:\n{history}"
    assert "already ran" in history.lower() or "already ran" in history, (
        f"Expected 'already ran' in history:\n{history}"
    )
    assert nmap_cmd in history, f"Expected command in history:\n{history}"
    assert "different" in history.lower(), (
        f"Expected 'different' prompt in history:\n{history}"
    )
