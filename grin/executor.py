"""The Executor — Grin's first AI agent. A bounded observe-act loop: ask a local model for
the next action, submit it to the SP1 spine (authorize/gate/execute/audit), feed the result
back, repeat until done / budget / a gated pause. The spine is still the sole execution path;
the Executor never runs a command itself."""
import uuid
from dataclasses import dataclass, field
from datetime import datetime

from grin.engagement import Engagement
from grin.extractors import extract, extract_findings
from grin.lootfile import persist_artifact, decrypt_persisted_key
from grin.journal import Journal, Step, journal_path
from grin.mode import resolve_mode
from grin.prompts import build_step_prompt, parse_step
from grin.spine import submit_action
from grin.results import ResultStore
from grin.brain import Brain

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


def _has_flag(journal) -> bool:
    return any(getattr(s, "label", "") == "flag" for s in journal.secrets)


def _closer_pass(eng, *, target, journal, runner, now, executed_commands, brain) -> bool:
    """Deterministic backstop: grin has a foothold but no flag. Run the matching deterministic helper
    (suid-hijack / sudo-gtfo / ssh-loot / web-rce) THROUGH THE SPINE — no model in the loop — and
    capture the flag if one comes back. Returns True iff a flag was captured. This is what makes 6/6
    consistent despite a stochastic model."""
    from grin.closer import closer_commands, command_target
    if _has_flag(journal):
        return False
    # Up to 2 passes: pass 1 may run ENABLING steps (exfiltrate a key, scan for the pivot host);
    # pass 2 re-derives from the updated history so the now-possible ssh-loot pivot fires.
    for _pass in range(2):
        ran_any = False
        for cmd in closer_commands(journal.render_history(), target):
            norm = _canonical_cmd(cmd)
            if norm in executed_commands:
                continue
            tool = cmd.split()[0]
            # submit with the command's TRUE destination as the target, so the spine scope-checks the
            # real host the tool will hit (refuses an out-of-scope URL/host embedded in the command).
            dest = command_target(cmd, target)
            out = submit_action(eng, target=dest, tool=tool, command=cmd,
                                declared_class="post-exploit", runner=runner, now=now)
            executed_commands.add(norm)
            ran_any = True
            if out.status != "executed":
                continue
            raw = out.result.output or ""
            found = extract(tool, cmd, raw, dest)
            journal.add_step(Step(action={"tool": tool, "command": cmd, "target": target,
                                          "declared_class": "post-exploit",
                                          "why": "deterministic closer (model bypass)"},
                                  decision="executed", output=raw, exit_code=out.result.exit_code,
                                  extracted=[{"label": s.label, "value": s.value} for s in found]))
            existing_keys = {(s.label, s.value) for s in journal.secrets}
            for sec in found:
                if (sec.label, sec.value) not in existing_keys:
                    journal.secrets.append(sec)
                    existing_keys.add((sec.label, sec.value))
                    persist_artifact(sec, runner, target=target)
            if _has_flag(journal):
                if brain is not None:
                    from grin.brain import reinforce_success
                    reinforce_success(brain, journal.render_history(), target)
                return True
        if not ran_any:
            break
    return False


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
                 executed_commands: set | None = None, brain: "Brain | None" = None,
                 should_stop=None) -> TaskResult:
    # Grin Brain: load (and seed once) the persistent lessons store unless a caller injected one
    # (tests pass their own / None-via-env). Failures here must never break a run.
    if brain is None:
        try:
            brain = Brain()
            brain.ensure_seeded()
        except Exception:  # noqa: BLE001
            brain = None
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
    recon_count: dict = {}   # (tool, target) -> times a recon tool has run; caps the re-scan loop

    # Behavioral mode (CTF vs assessment) is constant for the task: assessment when the engagement
    # opts in OR the target is a web URL; otherwise CTF (the unchanged default).
    _target_type = "web-url" if str(target).lower().startswith(("http://", "https://")) else ""
    step_mode = resolve_mode("assessment" if getattr(eng, "assess", False) else "", _target_type)

    while len(journal.steps) < journal.max_steps:
        # Operator hit Stop: bail immediately, mid-objective (not just between objectives).
        if should_stop is not None and should_stop():
            journal.save()
            return TaskResult("completed", journal.findings, journal, secrets=journal.secrets)
        system, user = build_step_prompt(objective, target, journal, eng.roe.allowed_actions,
                                         brain=brain, mode=step_mode)
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
            # Merge model-reported findings with the deterministic ones already recorded (e.g. nuclei),
            # dedup by title — so model claims add to, never erase, evidence-backed auto-findings.
            merged = list(journal.findings)
            _ft = {f.title for f in merged}
            for fnd in (decision.findings or []):
                if fnd.title not in _ft:
                    merged.append(fnd)
                    _ft.add(fnd.title)
            journal.set_findings(merged)
            # Merge model-reported secrets with already auto-extracted secrets so
            # neither source overwrites the other. Dedup by (label, value).
            existing = list(journal.secrets)
            existing_keys = {(s.label, s.value) for s in existing}
            for sec in (decision.secrets or []):
                if (sec.label, sec.value) not in existing_keys:
                    existing.append(sec)
                    existing_keys.add((sec.label, sec.value))
            journal.set_secrets(existing)
            # The model thinks it's done. If it has NOT actually captured a flag but a foothold
            # exists, run the deterministic closer before accepting 'done' (fixes premature-done).
            if not _has_flag(journal):
                _closer_pass(eng, target=target, journal=journal, runner=runner, now=now,
                             executed_commands=executed_commands, brain=brain)
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

        # Anti-loop: recon tools (nmap/masscan) re-run with slightly different flags don't dedup, so
        # the agent can spin re-scanning the same host forever. Cap recon at 2 runs per (tool,target);
        # after that it's treated as non-progress so the loop moves on / aborts instead of re-scanning.
        _t0 = (a["command"] or "").split()[0] if (a["command"] or "").split() else ""
        if _t0 in ("nmap", "masscan", "rustscan"):
            rk = (_t0, a["target"])
            recon_count[rk] = recon_count.get(rk, 0) + 1
            if recon_count[rk] > 2:
                journal.add_step(Step(action=a, decision="duplicate",
                                      reason="recon already done on this target — stop re-scanning"))
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
            # Deterministic findings (nuclei): record vuln hits as evidence-backed findings,
            # model-independent — broad real-world coverage that doesn't rely on the model reporting.
            existing_titles = {f.title for f in journal.findings}
            for fnd in extract_findings(a["tool"], a["command"], raw_output, a["target"]):
                if fnd.title not in existing_titles:
                    journal.findings.append(fnd)
                    existing_titles.add(fnd.title)
            # A captured flag is terminal proof for this objective — finish now instead of taking
            # more steps. (The Orchestrator decides whether the whole engagement is done.)
            if any(getattr(s, "label", "") == "flag" for s in found_secrets):
                if brain is not None:
                    from grin.brain import reinforce_success
                    reinforce_success(brain, journal.render_history(), target)
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

    # Budget spent without a flag: last-resort deterministic closer through the spine.
    if _closer_pass(eng, target=target, journal=journal, runner=runner, now=now,
                    executed_commands=executed_commands, brain=brain):
        journal.save()
        return TaskResult("completed", journal.findings, journal, secrets=journal.secrets)
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
