"""Deterministic extractor integration tests for the Executor.

Proves that creds/flags found in tool output are captured into
TaskResult.secrets and surfaced in render_history even when the model
never mentions them in its `done` reply.
"""
import json
from datetime import datetime

import pytest

from grin.engagement import validate_engagement
from grin.executor import execute_task, MAX_NOPROGRESS
from grin.inference import FakeClient
from grin.journal import Journal, Step
from grin.runner import ExecResult
from grin.secret import Secret

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


def _done(findings=None, secrets=None):
    return json.dumps({"done": True, "findings": findings or [],
                       "secrets": secrets or []})


class FakeRunnerWithOutput:
    """Runner that returns a fixed output for a given command."""

    def __init__(self, outputs: dict):
        self._outputs = outputs

    def run(self, target: str, command: str, timeout: int = 60) -> ExecResult:
        if command in self._outputs:
            return self._outputs[command]
        return ExecResult(output=f"[fake: {command}]", exit_code=0,
                          duration_s=0.0, timed_out=False)


TARGET = "203.0.113.7"
HYDRA_CMD = f"hydra -L users.txt -P pass.txt ssh://{TARGET}"
HYDRA_OUT = (
    f"[DATA] attacking ssh://{TARGET}:22/\n"
    f"[22][ssh] host: {TARGET}   login: admin   password: password\n"
    "1 of 1 target successfully completed\n"
)


# ---------------------------------------------------------------------------
# Test 1: extractor captures cred even if model reports no secrets in `done`
# ---------------------------------------------------------------------------

def test_extractor_captures_cred_model_reports_nothing(tmp_path):
    """Hydra outputs a found credential. The model's done reply lists no secrets.
    TaskResult.secrets must still contain the extracted credential."""
    eng = make_eng(tmp_path)
    client = FakeClient([
        _action("hydra", HYDRA_CMD, TARGET, "exploit"),
        _done(),  # model reports nothing
    ])
    runner = FakeRunnerWithOutput({HYDRA_CMD: ExecResult(HYDRA_OUT, 0, 2.0, False)})

    res = execute_task(eng, objective="crack SSH", target=TARGET,
                       client=client, runner=runner, now=NOW, max_steps=10)

    assert res.status == "completed"
    creds = [s for s in res.secrets if s.label == "SSH credentials"]
    assert len(creds) == 1, f"Expected 1 extracted credential, got: {res.secrets}"
    assert creds[0].value == "admin:password"
    assert creds[0].target == TARGET
    assert creds[0].tool == "hydra"


# ---------------------------------------------------------------------------
# Test 2: extractor + model secrets merge (no double-count)
# ---------------------------------------------------------------------------

def test_extractor_and_model_secrets_merge(tmp_path):
    """Hydra extracts a cred; the model also reports a different secret.
    Both must appear in TaskResult.secrets (merged, not one overwriting the other)."""
    eng = make_eng(tmp_path)
    model_secret = {"label": "sudo password", "value": "admin:password2",
                    "target": TARGET, "tool": "hydra", "command": HYDRA_CMD, "context": ""}
    client = FakeClient([
        _action("hydra", HYDRA_CMD, TARGET, "exploit"),
        _done(secrets=[model_secret]),
    ])
    runner = FakeRunnerWithOutput({HYDRA_CMD: ExecResult(HYDRA_OUT, 0, 2.0, False)})

    res = execute_task(eng, objective="crack SSH", target=TARGET,
                       client=client, runner=runner, now=NOW, max_steps=10)

    assert res.status == "completed"
    labels = {s.label for s in res.secrets}
    assert "SSH credentials" in labels, "extractor secret missing"
    assert "sudo password" in labels, "model secret missing"
    assert len(res.secrets) == 2, f"Expected 2 secrets (no dup), got: {res.secrets}"


# ---------------------------------------------------------------------------
# Test 3: extractor captures flag
# ---------------------------------------------------------------------------

def test_extractor_captures_flag(tmp_path):
    """A command prints a GRIN{...} flag. TaskResult.secrets contains it."""
    eng = make_eng(tmp_path)
    flag_cmd = f"sshpass -p password ssh admin@{TARGET} cat /root/flag.txt"
    flag_out = "GRIN{b460fd956b584a5faefe7c92e36744f4}"
    client = FakeClient([
        _action("sshpass", flag_cmd, TARGET, "exploit"),
        _done(),
    ])
    runner = FakeRunnerWithOutput({flag_cmd: ExecResult(flag_out, 0, 1.0, False)})

    res = execute_task(eng, objective="read flag", target=TARGET,
                       client=client, runner=runner, now=NOW, max_steps=10)

    assert res.status == "completed"
    flags = [s for s in res.secrets if s.label == "flag"]
    assert len(flags) == 1
    assert flags[0].value == "GRIN{b460fd956b584a5faefe7c92e36744f4}"


# ---------------------------------------------------------------------------
# Test 4: render_history surfaces extracted credential
# ---------------------------------------------------------------------------

def test_render_history_surfaces_extracted_credential(tmp_path):
    """After a hydra step, render_history must include an [auto-extracted: ...] line."""
    task_id = "abcd1234"
    j = Journal(
        task_id=task_id,
        objective="crack SSH",
        target=TARGET,
        engagement_path=str(tmp_path / "audit" / "e1.jsonl"),
        path=str(tmp_path / f"e1.{task_id}.journal.json"),
        max_steps=12,
    )
    j.add_step(Step(
        action={"tool": "hydra", "command": HYDRA_CMD, "target": TARGET,
                "declared_class": "exploit", "why": "brute force"},
        decision="executed",
        output=HYDRA_OUT,
        exit_code=0,
        extracted=[{"label": "SSH credentials", "value": "admin:password"}],
    ))

    history = j.render_history()

    assert "auto-extracted" in history, f"Expected [auto-extracted:] in history:\n{history}"
    assert "admin:password" in history, f"Expected credential value in history:\n{history}"
    assert "SSH credentials" in history, f"Expected label in history:\n{history}"


# ---------------------------------------------------------------------------
# Test 5: no extraction when output is empty (no noise)
# ---------------------------------------------------------------------------

def test_no_extraction_on_empty_output(tmp_path):
    """A command that produces no output should not add any extractor secrets."""
    eng = make_eng(tmp_path)
    plain_cmd = f"nmap -sV {TARGET}"
    client = FakeClient([
        _action("nmap", plain_cmd, TARGET, "active-scan"),
        _done(),
    ])
    runner = FakeRunnerWithOutput({plain_cmd: ExecResult("22/tcp open ssh", 0, 0.5, False)})

    res = execute_task(eng, objective="scan", target=TARGET,
                       client=client, runner=runner, now=NOW, max_steps=10)

    assert res.status == "completed"
    # nmap output doesn't contain hydra creds or flags → no extracted secrets
    assert res.secrets == [], f"Expected no secrets, got: {res.secrets}"


# ---------------------------------------------------------------------------
# Test 6: extractor deduplicates — same cred from two runs
# ---------------------------------------------------------------------------

def test_extractor_deduplicates_across_steps(tmp_path):
    """If two separate tool executions return the same credential, it must appear only once."""
    eng = make_eng(tmp_path)
    cmd1 = f"hydra -l admin -P list1.txt ssh://{TARGET}"
    cmd2 = f"hydra -l admin -P list2.txt ssh://{TARGET}"
    same_out = f"[22][ssh] host: {TARGET}   login: admin   password: password\n"

    client = FakeClient([
        _action("hydra", cmd1, TARGET, "exploit"),
        _action("hydra", cmd2, TARGET, "exploit"),
        _done(),
    ])
    runner = FakeRunnerWithOutput({
        cmd1: ExecResult(same_out, 0, 1.0, False),
        cmd2: ExecResult(same_out, 0, 1.0, False),
    })

    res = execute_task(eng, objective="crack", target=TARGET,
                       client=client, runner=runner, now=NOW, max_steps=10)

    assert res.status == "completed"
    creds = [s for s in res.secrets if s.label == "SSH credentials"]
    assert len(creds) == 1, f"Expected 1 deduped credential, got: {creds}"
