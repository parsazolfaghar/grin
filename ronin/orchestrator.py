"""The Orchestrator — Ronin's engagement brain. An adaptive loop: plan objectives, run each via
the SP2 Executor, dedup findings, let the Analyst chase leads + decide done, repeat until done /
objective-budget / empty queue. Pure coordination: it never runs tools or touches the spine —
all execution flows through execute_task -> submit_action -> the SP1 gatekeeper."""
from dataclasses import dataclass, field
from datetime import datetime

from ronin.analyst import initial_plan, replan
from ronin.engagement import Engagement
from ronin.executor import execute_task, DEFAULT_MODEL


@dataclass
class EngagementResult:
    status: str                 # completed | budget_exhausted | model_unavailable
    findings: list = field(default_factory=list)
    objectives_run: list = field(default_factory=list)
    paused: list = field(default_factory=list)      # [{objective, pending_id, journal}]
    plan_log: list = field(default_factory=list)


def _merge_findings(into: list, new) -> None:
    """Deterministic exact-duplicate dedup; never drops a distinct finding."""
    for f in new:
        if f not in into:
            into.append(f)


def orchestrate(eng: Engagement, *, goal: str, planner_client, executor_client, runner,
                now: datetime, model: str = DEFAULT_MODEL, max_objectives: int = 10,
                max_steps: int = 12, seeds=None, engagement_path: str = "") -> EngagementResult:
    if not planner_client.is_up():
        return EngagementResult("model_unavailable")

    queue = initial_plan(planner_client, model, goal, eng.scope.include, seeds or [])
    findings: list = []
    objectives_run: list = []
    paused: list = []
    plan_log: list = [{"kind": "initial_plan", "objectives": list(queue)}]

    while queue and len(objectives_run) < max_objectives:
        obj = queue.pop(0)
        res = execute_task(eng, objective=obj.objective, target=obj.target,
                           client=executor_client, runner=runner, now=now, model=model,
                           max_steps=max_steps, engagement_path=engagement_path)
        objectives_run.append(obj)
        _merge_findings(findings, res.findings)
        if res.status == "awaiting_approval":
            paused.append({"objective": obj, "pending_id": res.pending_id,
                           "journal": res.journal.path})
            # Don't replan on a paused task — we don't know its outcome yet.
            # Continue draining the queue so other objectives still run.
            continue

        decision = replan(planner_client, model, goal, findings, len(objectives_run), len(queue))
        plan_log.append({"kind": "replan", "done": decision.done, "reason": decision.reason,
                         "objectives": list(decision.next_objectives)})
        if decision.done:
            return EngagementResult("completed", findings, objectives_run, paused, plan_log)
        for o in decision.next_objectives:
            queue.append(o)

    status = "budget_exhausted" if len(objectives_run) >= max_objectives and queue else "completed"
    return EngagementResult(status, findings, objectives_run, paused, plan_log)
