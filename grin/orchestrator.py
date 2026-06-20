"""The Orchestrator — Grin's engagement brain. An adaptive loop: plan objectives, run each via
the SP2 Executor, dedup findings, let the Analyst chase leads + decide done, repeat until done /
objective-budget / empty queue. Pure coordination: it never runs tools or touches the spine —
all execution flows through execute_task -> submit_action -> the SP1 gatekeeper."""
from dataclasses import dataclass, field
from datetime import datetime

from grin.aggressive import sweep_objectives, discovered_services
from grin.analyst import initial_plan, replan
from grin.checkpoint import new_flags, route_queue
from grin.discoveries import discover
from grin.engagement import Engagement
from grin.executor import execute_task, resume_task, DEFAULT_MODEL
from grin.finding import Finding
from grin.objective import Objective
from grin.honeypot import assess as _assess_honeypot
from grin.journal import Journal
from grin.loot import LootStore, loot_dir
from grin.results import ResultStore, results_path

_HONEYPOT_TITLE = "Suspected honeypot/decoy (advisory)"

# Consecutive objectives that add no new finding/secret before the loop concludes a non-aggressive
# engagement has stalled (nothing more to find here) — stops flailing to the objective budget.
MAX_STALL_OBJECTIVES = 2

# How many times the Medic (grin/medic.py) may be paged per engagement before it concludes —
# bounds the rescue loop so a stall can't spin the Medic forever.
MAX_MEDIC_PAGES = 2

# Objectives of command activity with NO new finding/secret before the Medic is paged. Catches
# "productive wandering" — an agent that keeps producing output (so the dead-stall never trips)
# but never actually captures anything. The dead stall handles "no activity at all".
MEDIC_NOCAPTURE_TRIGGER = 3


def _has_flag(secrets) -> bool:
    return any(getattr(s, "label", "") == "flag" for s in secrets)


def _discovery_keys(journal) -> set:
    """Deterministic 'what did recon learn' keys for THIS task: a key per live host and per
    host:port service found in the task's executed tool output. Used so the no-progress stall counter
    treats genuine recon (new hosts/services) as progress — a network sweep that keeps finding live
    hosts is making progress even though it produces no findings/secrets yet."""
    recs = []
    for s in getattr(journal, "steps", []) or []:
        if getattr(s, "decision", "") != "executed":
            continue
        a = s.action if isinstance(s.action, dict) else {}
        recs.append({"command": a.get("command", ""), "output": getattr(s, "output", ""),
                     "target": a.get("target", "")})
    keys = set()
    for h in discover(recs).hosts:
        keys.add(("h", h.target))
        for svc in h.services:
            keys.add(("s", h.target, svc.port))
    return keys


def _output_keys(journal) -> set:
    """Keys for genuinely NEW tool output in this task. The agent learning something new — an RCE
    enumerating files, a shell reading a config — is real progress even before it yields a formal
    finding/secret. Counting this stops the no-progress stall from killing an engagement that is
    actively winning (the bug that cut T5 off at 3 objectives right after it achieved RCE). Empty
    output doesn't count, so a genuinely spinning agent still stalls; cross-objective command dedup
    already blocks identical re-runs, so distinct non-empty outputs ~= distinct successful steps."""
    import hashlib
    keys = set()
    for s in getattr(journal, "steps", []) or []:
        if getattr(s, "decision", "") != "executed":
            continue
        out = (getattr(s, "output", "") or "").strip()
        if out:
            keys.add(hashlib.sha1(out.encode("utf-8", "replace")).hexdigest())
    return keys


def _flag_honeypot(findings: list) -> None:
    """ADVISORY ONLY (roadmap R1): if accumulated findings look like a decoy, append ONE info
    finding (once). Never blocks, removes objectives, or gates execution — the operator decides."""
    if any(getattr(f, "title", "") == _HONEYPOT_TITLE for f in findings):
        return
    a = _assess_honeypot(findings)
    if a.suspected:
        findings.append(Finding(
            title=_HONEYPOT_TITLE, target="(engagement)", severity="info",
            evidence=a.detail, tool="honeypot-detector", command="",
            recommendation="Advisory only — verify before further exploitation; the engagement continues."))


@dataclass
class EngagementResult:
    status: str                 # completed | budget_exhausted | model_unavailable
    findings: list = field(default_factory=list)
    objectives_run: list = field(default_factory=list)
    paused: list = field(default_factory=list)      # [{objective, pending_id, journal}]
    plan_log: list = field(default_factory=list)
    goal: str = ""
    secrets: list = field(default_factory=list)


def _write_medic_patch(eng, patch: str, diagnosis: str) -> str | None:
    """Write a Medic patch PROPOSAL to a review file next to the audit log. Human-review only — the
    engine NEVER applies it. Returns the path, or None on error (best-effort, never blocks a run)."""
    try:
        import os
        audit = getattr(eng, "audit_log", "") or ""
        d = os.path.dirname(audit) or "."
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, f"{getattr(eng, 'id', 'engagement')}.medic-patch.md")
        with open(path, "a") as f:
            f.write(f"# Medic patch proposal (REVIEW ONLY — not applied)\n\n"
                    f"## Diagnosis\n{diagnosis}\n\n## Proposed change\n{patch}\n\n---\n")
        return path
    except Exception:
        return None


def _merge_findings(into: list, new) -> None:
    """Deterministic exact-duplicate dedup; never drops a distinct finding."""
    for f in new:
        if f not in into:
            into.append(f)


def _model_for(objective, objective_models, base: str) -> str:
    """Advisory model routing: pick the model for an objective by its action_class hint.
    Falls back to the base model when there's no map or the class isn't mapped. Routing only —
    the spine still resolves and authorizes each actual command."""
    if objective_models and objective.action_class in objective_models:
        return objective_models[objective.action_class]
    return base


def _drive_loop(eng: Engagement, *, goal: str, queue: list, findings: list,
                objectives_run: list, paused: list, plan_log: list, planner_client,
                executor_client, runner, now: datetime, planner_model: str,
                objective_models, base_model: str, max_objectives: int,
                max_steps: int, engagement_path: str, secrets: list, loot,
                scope_targets: list, aggressive: bool = False, catalog=None,
                seen: set = None, checkpoint_fn=None, should_stop=None,
                medic_triage=None, medic_patches: bool = False) -> str:
    """The adaptive loop body, shared by orchestrate() and resume_engagement(). Mutates the
    passed-in lists; returns the final status (completed | budget_exhausted).

    When aggressive=True and a catalog is provided, the loop re-sweeps for new techniques after
    each objective (seeded from discovered services in findings) and ignores the planner's done
    signal until the queue is exhausted / budget is hit."""
    if seen is None:
        seen = set()
    if medic_triage is None:
        from grin.medic import triage as medic_triage
    medic_pages = 0
    no_capture = 0            # objectives since the last NEW finding/secret (activity != capture)
    recent_steps: list = []   # compact cross-objective command trail for the Medic

    def _page_medic():
        nonlocal medic_pages
        d = medic_triage(planner_client, planner_model, goal=goal, findings=findings,
                         secrets=secrets, tried_objectives=objectives_run,
                         recent_steps=recent_steps, scope_targets=scope_targets,
                         propose_patches=medic_patches)
        medic_pages += 1
        plan_log.append({"kind": "medic", "action": d.action,
                         "objectives": list(d.objectives), "diagnosis": d.diagnosis,
                         "patch": getattr(d, "patch", "")})
        if getattr(d, "patch", ""):
            _write_medic_patch(eng, d.patch, d.diagnosis)
        # Grin Brain: a Medic page means grin hit a wall here. Record a pitfall against the situations
        # active in the recent trail so the next run goes straight to the deterministic helper for
        # that situation instead of looping. This is how the Medic makes grin learn from failure.
        try:
            from grin.brain import Brain, detect_situations, learn_failure
            hist = " ".join(str(getattr(s, "output", "") or s) for s in recent_steps)
            sits = detect_situations(hist)
            _b = Brain()
            for sit in sits:
                learn_failure(_b, sit,
                              "grin STALLED here before (Medic paged) — go straight to the proven "
                              "deterministic helper for this situation; do not loop or re-enumerate.")
        except Exception:  # noqa: BLE001 - learning must never break the engagement
            pass
        return d

    def _apply_recover(d) -> bool:
        added = False
        for o in d.objectives:
            key = (o.objective, o.target)
            if key not in seen:
                seen.add(key)
                queue.append(o)
                added = True
        return added

    # shared across objectives so a command run earlier is skipped later (stops cross-objective
    # repetition — the #1 cause of flailing). Each engagement loop gets its own set.
    executed_commands: set = set()
    flagged_seen: set = set()
    discovered_keys: set = set()   # cumulative live hosts + host:port services found by recon
    output_keys: set = set()       # cumulative distinct non-empty tool outputs (exploitation progress)
    focus_target = None
    stall = 0
    while queue and len(objectives_run) < max_objectives:
        if should_stop is not None and should_stop():   # operator hit Stop — end between objectives
            return "stopped"
        obj = queue.pop(0)
        prev_progress = len(findings) + len(secrets) + len(discovered_keys) + len(output_keys)
        prev_findsec = len(findings) + len(secrets)
        res = execute_task(eng, objective=obj.objective, target=obj.target,
                           client=executor_client, runner=runner, now=now,
                           model=_model_for(obj, objective_models, base_model),
                           max_steps=max_steps, engagement_path=engagement_path,
                           executed_commands=executed_commands, should_stop=should_stop)
        objectives_run.append(obj)
        _merge_findings(findings, res.findings)
        _flag_honeypot(findings)   # advisory; never alters the queue/execution
        for sec in res.secrets:
            if sec not in secrets:
                secrets.append(sec)
                loot.record(sec, objective=obj.objective)
        for st in getattr(res.journal, "steps", None) or []:
            if getattr(st, "decision", None) == "executed":
                recent_steps.append({
                    "objective": obj.objective,
                    "command": (getattr(st, "action", None) or {}).get("command", ""),
                    "exit_code": getattr(st, "exit_code", None),
                    "output": getattr(st, "output", "") or "",
                    "extracted": [e.get("label") for e in (getattr(st, "extracted", None) or [])],
                })
        recent_steps[:] = recent_steps[-60:]
        if res.status == "awaiting_approval":
            paused.append({"objective": obj, "pending_id": res.pending_id,
                           "journal": res.journal.path})
            continue
        # Goal-met early exit: a captured flag is terminal proof. Non-aggressive runs stop the moment
        # one is in hand rather than burning the rest of the budget. (Aggressive mode sweeps the whole
        # catalog and ignores done by design, so this is gated off there.)
        if not aggressive and _has_flag(secrets):
            return "completed"
        # No-progress termination: consecutive objectives that add nothing new mean the engagement
        # has stalled — conclude instead of flailing to the budget. (Aggressive sweeps deliberately.)
        # Recon counts: new live hosts / services reset the stall so a sweep that's still finding
        # hosts is not mistaken for stalling (the bug that quit a /24 scan after pure recon).
        # exploitation progress counts too: a task that achieved RCE / read new files learned
        # something new even with no formal finding yet — don't mistake that for stalling.
        discovered_keys |= _discovery_keys(res.journal)
        output_keys |= _output_keys(res.journal)
        no_capture = no_capture + 1 if len(findings) + len(secrets) == prev_findsec else 0
        if not aggressive:
            # Dead stall: no progress of ANY kind (findings/secrets/recon/output). Page the Medic
            # before concluding; it recovers or hands back a diagnosis.
            if len(findings) + len(secrets) + len(discovered_keys) + len(output_keys) == prev_progress:
                stall += 1
                if stall >= MAX_STALL_OBJECTIVES:
                    if medic_pages < MAX_MEDIC_PAGES:
                        decision = _page_medic()
                        if decision.action == "recover" and _apply_recover(decision):
                            stall = 0
                            no_capture = 0
                            continue
                        findings.append(Finding(
                            title="Medic diagnosis", target=obj.target, severity="info",
                            evidence=decision.diagnosis, tool="medic", command="",
                            recommendation=""))
                        return "completed"
                    return "completed"
            else:
                stall = 0
            # Productive-wandering rescue: output is moving but nothing is being CAPTURED. Page the
            # Medic to redirect (e.g. "you have RCE — read the flag") before the budget runs out.
            if no_capture >= MEDIC_NOCAPTURE_TRIGGER and medic_pages < MAX_MEDIC_PAGES:
                decision = _page_medic()
                no_capture = 0
                if decision.action == "recover" and _apply_recover(decision):
                    stall = 0
                    continue
                # eager conclude: nothing new to try right now — let the run proceed/end normally
        if aggressive and checkpoint_fn is not None:
            fresh = new_flags(res.secrets, flagged_seen)
            for f in fresh:
                flagged_seen.add(f)
            if fresh:
                decision = checkpoint_fn(fresh[-1], obj.target)
                queue[:], ft, stop = route_queue(decision, queue, obj.target)
                if ft is not None:
                    focus_target = ft
                if stop:
                    return "completed"
        if aggressive and catalog is not None:
            svcs = discovered_services(findings)
            for o in sweep_objectives(catalog, eng.scope.include, svcs):
                if focus_target is not None and o.target != focus_target:
                    continue
                key = (o.objective, o.target)
                if key not in seen:
                    seen.add(key)
                    queue.append(o)
        decision = replan(planner_client, planner_model, goal, findings,
                          len(objectives_run), len(queue), scope_targets, secrets=secrets)
        plan_log.append({"kind": "replan", "done": decision.done, "reason": decision.reason,
                         "objectives": list(decision.next_objectives)})
        if decision.done and not aggressive:
            return "completed"
        for o in decision.next_objectives:
            queue.append(o)
    return "budget_exhausted" if queue else "completed"


def orchestrate(eng: Engagement, *, goal: str, planner_client, executor_client, runner,
                now: datetime, model: str = DEFAULT_MODEL, planner_model: str | None = None,
                objective_models=None, max_objectives: int = 10, max_steps: int = 12,
                seeds=None, engagement_path: str = "", aggressive: bool = False,
                catalog=None, checkpoint_fn=None, should_stop=None,
                medic_patches: bool = False) -> EngagementResult:
    if not planner_client.is_up():
        return EngagementResult("model_unavailable", goal=goal)

    if eng.stealth != "off":
        from grin.spine import apply_device_stealth
        apply_device_stealth(eng, runner=runner)

    eff_planner = planner_model or model
    queue = initial_plan(planner_client, eff_planner, goal, eng.scope.include, seeds or [])
    if not queue:
        # Cold-start fallback: the planner returned no objectives (a model hiccup). Don't silently
        # no-op with 0 objectives — seed a recon objective per in-scope target so the engagement
        # actually runs (the Medic + normal flow take over from there).
        queue = [Objective("enumerate services and identify the vulnerability to exploit", t,
                           "active-scan") for t in eng.scope.include]
    findings: list = []
    objectives_run: list = []
    paused: list = []
    plan_log: list = [{"kind": "initial_plan", "objectives": list(queue)}]
    secrets: list = []
    loot = LootStore(loot_dir(eng))

    seen: set = set()
    if aggressive and catalog is not None:
        seed = sweep_objectives(catalog, eng.scope.include, {})
        for o in seed:
            seen.add((o.objective, o.target))
        queue = seed + queue

    status = _drive_loop(eng, goal=goal, queue=queue, findings=findings,
                         objectives_run=objectives_run, paused=paused, plan_log=plan_log,
                         planner_client=planner_client, executor_client=executor_client,
                         runner=runner, now=now, planner_model=eff_planner,
                         objective_models=objective_models, base_model=model,
                         max_objectives=max_objectives, max_steps=max_steps,
                         engagement_path=engagement_path, secrets=secrets, loot=loot,
                         scope_targets=eng.scope.include, aggressive=aggressive,
                         catalog=catalog, seen=seen, checkpoint_fn=checkpoint_fn, should_stop=should_stop,
                         medic_patches=medic_patches)
    return EngagementResult(status, findings, objectives_run, paused, plan_log, goal=goal,
                            secrets=secrets)


def resume_engagement(eng: Engagement, prior: EngagementResult, *, planner_client,
                      executor_client, runner, now: datetime, model: str = DEFAULT_MODEL,
                      planner_model: str | None = None, objective_models=None,
                      max_objectives: int = 10, max_steps: int = 12,
                      engagement_path: str = "", checkpoint_fn=None, should_stop=None) -> EngagementResult:
    """Continue a gated engagement after `grin gate` approvals. A paused objective whose
    pending action is present in the results store (approved) is resumed via resume_task; one
    that's absent (still pending / denied) stays paused. After resuming, the adaptive loop
    continues within budget. No approved objective => prior state is returned unchanged."""
    eff_planner = planner_model or model
    goal = prior.goal
    findings = list(prior.findings)
    objectives_run = list(prior.objectives_run)   # paused objectives are already counted here
    plan_log = list(prior.plan_log)
    paused: list = []
    secrets = list(prior.secrets)
    loot = LootStore(loot_dir(eng))
    store = ResultStore(results_path(eng))
    resumed_any = False

    for p in prior.paused:
        if store.get(p["pending_id"]) is None:
            paused.append(p)
            continue
        resumed_any = True
        res = resume_task(eng, Journal.load(p["journal"]), client=executor_client,
                          runner=runner, now=now, result_store=store,
                          model=_model_for(p["objective"], objective_models, model))
        _merge_findings(findings, res.findings)
        for sec in res.secrets:
            if sec not in secrets:
                secrets.append(sec)
                loot.record(sec, objective=p["objective"].objective)
        if res.status == "awaiting_approval":
            paused.append({"objective": p["objective"], "pending_id": res.pending_id,
                           "journal": res.journal.path})

    if not resumed_any:
        return EngagementResult(prior.status, findings, objectives_run, paused, plan_log,
                                goal=goal, secrets=secrets)

    queue: list = []
    if len(objectives_run) < max_objectives:
        decision = replan(planner_client, eff_planner, goal, findings, len(objectives_run), 0,
                          eng.scope.include, secrets=secrets)
        plan_log.append({"kind": "replan", "done": decision.done, "reason": decision.reason,
                         "objectives": list(decision.next_objectives)})
        if decision.done:
            return EngagementResult("completed", findings, objectives_run, paused, plan_log,
                                    goal=goal, secrets=secrets)
        queue = list(decision.next_objectives)

    status = _drive_loop(eng, goal=goal, queue=queue, findings=findings,
                         objectives_run=objectives_run, paused=paused, plan_log=plan_log,
                         planner_client=planner_client, executor_client=executor_client,
                         runner=runner, now=now, planner_model=eff_planner,
                         objective_models=objective_models, base_model=model,
                         max_objectives=max_objectives, max_steps=max_steps,
                         engagement_path=engagement_path, secrets=secrets, loot=loot,
                         scope_targets=eng.scope.include, checkpoint_fn=checkpoint_fn, should_stop=should_stop)
    return EngagementResult(status, findings, objectives_run, paused, plan_log, goal=goal,
                            secrets=secrets)
