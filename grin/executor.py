"""The Executor — Grin's first AI agent. A bounded observe-act loop: ask a local model for
the next action, submit it to the SP1 spine (authorize/gate/execute/audit), feed the result
back, repeat until done / budget / a gated pause. The spine is still the sole execution path;
the Executor never runs a command itself."""
import uuid
from dataclasses import dataclass, field
from datetime import datetime

from grin.engagement import Engagement
from grin.journal import Journal, Step, journal_path
from grin.prompts import build_step_prompt, parse_step
from grin.spine import submit_action
from grin.results import ResultStore

DEFAULT_MODEL = "qwen3:14b"   # config default; the real pin is set on the rig, not in code


@dataclass
class TaskResult:
    status: str                       # completed | awaiting_approval | budget_exhausted | model_unavailable
    findings: list
    journal: Journal
    pending_id: str | None = None
    secrets: list = field(default_factory=list)


def execute_task(eng: Engagement, *, objective: str, target: str, client, runner,
                 now: datetime, model: str = DEFAULT_MODEL, max_steps: int = 12,
                 journal: Journal | None = None, engagement_path: str = "") -> TaskResult:
    if journal is None:
        task_id = uuid.uuid4().hex[:8]
        journal = Journal(task_id=task_id, objective=objective, target=target,
                          engagement_path=engagement_path,
                          path=journal_path(eng, task_id), max_steps=max_steps)

    if not client.is_up():
        journal.save()
        return TaskResult("model_unavailable", journal.findings, journal,
                          secrets=journal.secrets)

    while len(journal.steps) < journal.max_steps:
        system, user = build_step_prompt(objective, target, journal, eng.roe.allowed_actions)
        raw = client.generate(model=model, system=system, prompt=user, temperature=0.3)
        decision = parse_step(raw, target)

        if decision.kind == "done":
            has_evidence = any(s.decision == "executed" for s in journal.steps)
            if (decision.findings or decision.secrets) and not has_evidence:
                # Evidence gate: don't accept findings/secrets until at least one tool actually ran.
                # Record a nudge step (shown in history) and keep looping within the budget.
                journal.add_step(Step(action={}, decision="no_evidence"))
                continue
            journal.set_findings(decision.findings or [])
            journal.set_secrets(decision.secrets or [])
            journal.save()
            return TaskResult("completed", journal.findings, journal,
                              secrets=journal.secrets)

        if decision.kind == "parse_miss":
            journal.add_step(Step(action={}, decision="parse_miss"))
            continue

        a = decision.action
        out = submit_action(eng, target=a["target"], tool=a["tool"], command=a["command"],
                            declared_class=a["declared_class"], runner=runner, now=now)
        if out.status == "executed":
            journal.add_step(Step(action=a, decision="executed",
                                  output=out.result.output, exit_code=out.result.exit_code))
        elif out.status == "refused":
            journal.add_step(Step(action=a, decision="refused", reason=out.reason))
        else:  # pending
            journal.add_step(Step(action=a, decision="pending", pending_id=out.pending_id))
            journal.awaiting_pending_id = out.pending_id
            journal.save()
            return TaskResult("awaiting_approval", journal.findings, journal,
                              pending_id=out.pending_id, secrets=journal.secrets)

    journal.save()
    return TaskResult("budget_exhausted", journal.findings, journal,
                      secrets=journal.secrets)


def resume_task(eng: Engagement, journal: Journal, *, client, runner, now: datetime,
                result_store: ResultStore, model: str = DEFAULT_MODEL) -> TaskResult:
    """Continue a paused task. The awaited (approved) action's full output is read from the
    results store; if it isn't there yet, the task stays awaiting_approval, unchanged.
    Resuming a journal that isn't awaiting approval (already completed / budget-exhausted)
    is a no-op — it must not issue new actions on a task the operator considers finished."""
    pid = journal.awaiting_pending_id
    if not pid:
        status = "completed" if journal.findings else "budget_exhausted"
        return TaskResult(status, journal.findings, journal)
    rec = result_store.get(pid)
    if rec is None:
        return TaskResult("awaiting_approval", journal.findings, journal, pending_id=pid)
    journal.update_pending_result(pid, rec.get("output", ""), rec.get("exit_code"))
    journal.save()
    return execute_task(eng, objective=journal.objective, target=journal.target,
                        client=client, runner=runner, now=now, model=model,
                        journal=journal)
