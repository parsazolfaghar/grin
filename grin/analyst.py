"""The Analyst — Grin's pure-LLM planning brain. It never touches tools or the spine; it only
reasons over findings to plan objectives. initial_plan seeds the queue; replan chases leads and
decides when the engagement goal is met. Tolerant JSON parsing, fail-soft on a miss."""
from dataclasses import dataclass

from grin.objective import Objective
from grin.classes import ACTION_CLASSES
from grin.jsonextract import extract_json

PLANNER_SYSTEM = (
    "You are Grin's Orchestrator/Analyst, planning an authorized, scope-bound penetration test. "
    "You decide which objectives to pursue; a separate Executor runs the tools under a fail-closed "
    "gatekeeper. Plan concrete objectives against in-scope targets only. Reply with ONE JSON "
    "object and nothing else."
)


def _extract_json(raw: str):
    # robust: first balanced JSON object bearing a planner key (handles trailing prose / echoed
    # example blocks). See grin/jsonextract.py.
    return extract_json(raw, want=("objectives", "next_objectives", "done"))


def _parse_objectives(items) -> list:
    out = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        objective = str(it.get("objective", "")).strip()
        target = str(it.get("target", "")).strip()
        if not (objective and target):
            continue
        ac = str(it.get("action_class", "")).strip().lower()
        if ac not in ACTION_CLASSES:
            ac = ""
        out.append(Objective(objective=objective, target=target, action_class=ac))
    return out


@dataclass
class AnalystDecision:
    next_objectives: list   # list[Objective]
    done: bool
    reason: str


def initial_plan(client, model: str, goal: str, scope_targets, seeds) -> list:
    user = (
        f"Engagement goal: {goal}\n"
        f"In-scope targets (patterns): {', '.join(scope_targets)}\n"
        f"Operator seed targets: {', '.join(seeds) if seeds else '(none)'}\n\n"
        "Produce the FIRST short list of objectives to pursue (usually start by enumerating/"
        "discovering hosts and services in scope). Each objective has a plain-language goal and a "
        "concrete in-scope target.\n"
        'Reply EXACTLY: {"objectives": [{"objective": "enumerate hosts", '
        '"target": "203.0.113.0/24", "action_class": "active-scan"}]} '
        '(action_class is one of passive|active-scan|exploit|post-exploit, your best guess for '
        'the objective).\nReturn ONLY the JSON.'
    )
    data = _extract_json(client.generate(model=model, system=PLANNER_SYSTEM, prompt=user,
                                         temperature=0.3))
    if isinstance(data, dict):
        return _parse_objectives(data.get("objectives", []))
    return []


def _render_findings(findings) -> str:
    if not findings:
        return "(no findings yet)"
    return "\n".join(f"- [{f.severity}] {f.title} ({f.target}) via {f.tool}" for f in findings)


def replan(client, model: str, goal: str, findings, done_count: int,
           remaining_count: int) -> AnalystDecision:
    user = (
        f"Engagement goal: {goal}\n"
        f"Objectives completed: {done_count}; still queued: {remaining_count}\n\n"
        f"Findings so far:\n{_render_findings(findings)}\n\n"
        "Decide: is the goal met (done)? If not, propose follow-up objectives that chase the most "
        "promising leads in the findings (in-scope targets only). Do not repeat completed work.\n"
        'Reply EXACTLY: {"done": false, "reason": "why", "next_objectives": '
        '[{"objective": "...", "target": "...", "action_class": "active-scan"}]}\n'
        "Return ONLY the JSON."
    )
    data = _extract_json(client.generate(model=model, system=PLANNER_SYSTEM, prompt=user,
                                         temperature=0.3))
    if isinstance(data, dict) and ("done" in data or "next_objectives" in data):
        return AnalystDecision(
            next_objectives=_parse_objectives(data.get("next_objectives", [])),
            done=bool(data.get("done", False)),
            reason=str(data.get("reason", "")).strip(),
        )
    return AnalystDecision(next_objectives=[], done=False, reason="unparseable analyst reply")
