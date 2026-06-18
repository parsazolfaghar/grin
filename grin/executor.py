"""The Executor — Grin's first AI agent. A bounded observe-act loop: ask a local model for
the next action, submit it to the SP1 spine (authorize/gate/execute/audit), feed the result
back, repeat until done / budget / a gated pause. The spine is still the sole execution path;
the Executor never runs a command itself."""
import uuid
from dataclasses import dataclass, field
from datetime import datetime

from grin.engagement import Engagement
from grin.extractors import extract
from grin.lootfile import persist_artifact, decrypt_persisted_key
from grin.journal import Journal, Step, journal_path
from grin.prompts import build_step_prompt, parse_step
from grin.spine import submit_action
from grin.results import ResultStore

DEFAULT_MODEL = "qwen3:14b"   # config default; the real pin is set on the rig, not in code

MAX_NOPROGRESS = 3  # consecutive non-advancing steps before the loop aborts


def _canonical_cmd(command: str) -> str:
    """Canonical dedup key: collapse whitespace and strip matching surrounding quotes from each token,
    so semantically identical retries dedup (e.g. `cat /root/flag.txt` == `cat "/root/flag.txt"` ==
    `cat '/root/flag.txt'`) — the T3 waste where the model re-tries the same read in different quoting.
    Deliberately does NOT strip a leading `sudo`/other prefix: `sudo cat X` is a different action."""
    toks = []
    for t in (command or "").split():
        if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'":
            t = t[1:-1]
        toks.append(t)
    return " ".join(toks)


@dataclass
class TaskResult:
    status: str                       # completed | awaiting_approval | budget_exhausted | model_unavailable
    findings: list
    journal: Journal
    pending_id: str | None = None
    secrets: list = field(default_factory=list)


def execute_task(eng: Engagement, *, objective: str, target: str, client, runner,
                 now: datetime, model: str = DEFAULT_MODEL, max_steps: int = 12,
                 journal: Journal | None = None, engagement_path: str = "",
                 executed_commands: set | None = None) -> TaskResult:
    if journal is None:
        task_id = uuid.uuid4().hex[:8]
        journal = Journal(task_id=task_id, objective=objective, target=target,
                          engagement_path=engagement_path,
                          path=journal_path(eng, task_id), max_steps=max_steps)

    if not client.is_up():
        journal.save()
        return TaskResult("model_unavailable", journal.findings, journal,
                          secrets=journal.secrets)

    # Command dedup. A caller (the Orchestrator) may pass a SHARED set so a command already run in
    # an EARLIER objective is skipped too — this is what stops the agent re-curling the same URL
    # across objectives. None -> a fresh per-task set (back-compatible).
    if executed_commands is None:
        executed_commands = set()
    noprogress = 0

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
                noprogress += 1
                if noprogress >= MAX_NOPROGRESS:
                    break
                continue
            journal.set_findings(decision.findings or [])
            # Merge model-reported secrets with already auto-extracted secrets so
            # neither source overwrites the other. Dedup by (label, value).
            existing = list(journal.secrets)
            existing_keys = {(s.label, s.value) for s in existing}
            for sec in (decision.secrets or []):
                if (sec.label, sec.value) not in existing_keys:
                    existing.append(sec)
                    existing_keys.add((sec.label, sec.value))
            journal.set_secrets(existing)
            journal.save()
            return TaskResult("completed", journal.findings, journal,
                              secrets=journal.secrets)

        if decision.kind == "parse_miss":
            journal.add_step(Step(action={}, decision="parse_miss"))
            noprogress += 1
            if noprogress >= MAX_NOPROGRESS:
                break
            continue

        a = decision.action
        normalized_cmd = _canonical_cmd(a["command"])

        # Dedup check: if this exact command has already been executed, skip it.
        if normalized_cmd in executed_commands:
            journal.add_step(Step(action=a, decision="duplicate"))
            noprogress += 1
            if noprogress >= MAX_NOPROGRESS:
                break
            continue

        out = submit_action(eng, target=a["target"], tool=a["tool"], command=a["command"],
                            declared_class=a["declared_class"], runner=runner, now=now)
        if out.status == "executed":
            raw_output = out.result.output or ""
            found_secrets = extract(a["tool"], a["command"], raw_output, a["target"])
            # Persist key/hash loot to a real file on the (objective-shared) runner so a LATER
            # objective's ssh2john/john/ssh can use it instead of guessing a path on the target.
            for sec in found_secrets:
                persist_artifact(sec, runner, target=a["target"])
                # A cracked passphrase: strip it from the persisted key in place so any later
                # `ssh -i /tmp/loot/id_rsa` works without carrying the passphrase across objectives.
                if sec.label == "cracked password":
                    decrypt_persisted_key(sec.value, runner, target=a["target"])
            extracted_tags = [{"label": s.label, "value": s.value} for s in found_secrets]
            journal.add_step(Step(action=a, decision="executed",
                                  output=raw_output, exit_code=out.result.exit_code,
                                  extracted=extracted_tags))
            executed_commands.add(normalized_cmd)
            noprogress = 0
            # Merge auto-extracted secrets into journal (model-independent capture).
            # Dedup by (label, value) — two secrets with the same label+value from
            # different commands are the same fact.
            existing_keys = {(s.label, s.value) for s in journal.secrets}
            for sec in found_secrets:
                if (sec.label, sec.value) not in existing_keys:
                    journal.secrets.append(sec)
                    existing_keys.add((sec.label, sec.value))
            # A captured flag is terminal proof for this objective — finish now instead of taking
            # more steps. (The Orchestrator decides whether the whole engagement is done.)
            if any(getattr(s, "label", "") == "flag" for s in found_secrets):
                journal.save()
                return TaskResult("completed", journal.findings, journal,
                                  secrets=journal.secrets)
        elif out.status == "refused":
            journal.add_step(Step(action=a, decision="refused", reason=out.reason))
            noprogress += 1
            if noprogress >= MAX_NOPROGRESS:
                break
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
        return TaskResult(status, journal.findings, journal, secrets=journal.secrets)
    rec = result_store.get(pid)
    if rec is None:
        return TaskResult("awaiting_approval", journal.findings, journal, pending_id=pid,
                          secrets=journal.secrets)
    journal.update_pending_result(pid, rec.get("output", ""), rec.get("exit_code"))
    journal.save()
    return execute_task(eng, objective=journal.objective, target=journal.target,
                        client=client, runner=runner, now=now, model=model,
                        journal=journal)
