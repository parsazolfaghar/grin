"""The Orchestrator — Grin's engagement brain. An adaptive loop: plan objectives, run each via
the SP2 Executor, dedup findings, let the Analyst chase leads + decide done, repeat until done /
objective-budget / empty queue. Pure coordination: it never runs tools or touches the spine —
all execution flows through execute_task -> submit_action -> the SP1 gatekeeper."""
from dataclasses import dataclass, field
from datetime import datetime

from grin.analyst import initial_plan, replan
from grin.engagement import Engagement
from grin.executor import execute_task, resume_task, DEFAULT_MODEL
from grin.journal import Journal
from grin.loot import LootStore, loot_dir
from grin.results import ResultStore, results_path


@dataclass
class EngagementResult:
    status: str                 # completed | budget_exhausted | model_unavailable
    findings: list = field(default_factory=list)
    objectives_run: list = field(default_factory=list)
    paused: list = field(default_factory=list)      # [{objective, pending_id, journal}]
    plan_log: list = field(default_factory=list)
    goal: str = ""
    secrets: list = field(default_factory=list)


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
                max_steps: int, engagement_path: str, secrets: list, loot) -> str:
    """The adaptive loop body, shared by orchestrate() and resume_engagement(). Mutates the
    passed-in lists; returns the final status (completed | budget_exhausted)."""
    while queue and len(objectives_run) < max_objectives:
        obj = queue.pop(0)
        res = execute_task(eng, objective=obj.objective, target=obj.target,
                           client=executor_client, runner=runner, now=now,
                           model=_model_for(obj, objective_models, base_model),
                           max_steps=max_steps, engagement_path=engagement_path)
        objectives_run.append(obj)
        _merge_findings(findings, res.findings)
        for sec in res.secrets:
            if sec not in secrets:
                secrets.append(sec)
                loot.record(sec, objective=obj.objective)
        if res.status == "awaiting_approval":
            paused.append({"objective": obj, "pending_id": res.pending_id,
                           "journal": res.journal.path})
            continue
        decision = replan(planner_client, planner_model, goal, findings,
                          len(objectives_run), len(queue))
        plan_log.append({"kind": "replan", "done": decision.done, "reason": decision.reason,
                         "objectives": list(decision.next_objectives)})
        if decision.done:
            return "completed"
        for o in decision.next_objectives:
            queue.append(o)
    return "budget_exhausted" if queue else "completed"


def orchestrate(eng: Engagement, *, goal: str, planner_client, executor_client, runner,
                now: datetime, model: str = DEFAULT_MODEL, planner_model: str | None = None,
                objective_models=None, max_objectives: int = 10, max_steps: int = 12,
                seeds=None, engagement_path: str = "") -> EngagementResult:
    if not planner_client.is_up():
        return EngagementResult("model_unavailable", goal=goal)

    eff_planner = planner_model or model
    queue = initial_plan(planner_client, eff_planner, goal, eng.scope.include, seeds or [])
    findings: list = []
    objectives_run: list = []
    paused: list = []
    plan_log: list = [{"kind": "initial_plan", "objectives": list(queue)}]
    secrets: list = []
    loot = LootStore(loot_dir(eng))

    status = _drive_loop(eng, goal=goal, queue=queue, findings=findings,
                         objectives_run=objectives_run, paused=paused, plan_log=plan_log,
                         planner_client=planner_client, executor_client=executor_client,
                         runner=runner, now=now, planner_model=eff_planner,
                         objective_models=objective_models, base_model=model,
                         max_objectives=max_objectives, max_steps=max_steps,
                         engagement_path=engagement_path, secrets=secrets, loot=loot)
    return EngagementResult(status, findings, objectives_run, paused, plan_log, goal=goal,
                            secrets=secrets)


def resume_engagement(eng: Engagement, prior: EngagementResult, *, planner_client,
                      executor_client, runner, now: datetime, model: str = DEFAULT_MODEL,
                      planner_model: str | None = None, objective_models=None,
                      max_objectives: int = 10, max_steps: int = 12,
                      engagement_path: str = "") -> EngagementResult:
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
        decision = replan(planner_client, eff_planner, goal, findings, len(objectives_run), 0)
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
                         engagement_path=engagement_path, secrets=secrets, loot=loot)
    return EngagementResult(status, findings, objectives_run, paused, plan_log, goal=goal,
                            secrets=secrets)
