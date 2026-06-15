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
        "Produce the FIRST short list of objectives to pursue. Start by enumerating/discovering "
        "hosts and services in scope — but that recon is only the FIRST STEP. The goal is to "
        "exploit what you find: capture the flag, obtain credentials, or gain access. Plan recon "
        "objectives now, and include at least one follow-on exploit objective so the model knows "
        "where recon leads.\n"
        "Reply EXACTLY with a JSON array of objectives. Example with two shapes:\n"
        '{"objectives": ['
        '{"objective": "enumerate open ports and services", "target": "<in-scope-target>", '
        '"action_class": "active-scan"}, '
        '{"objective": "exploit the identified service to gain access", "target": "<in-scope-target>", '
        '"action_class": "exploit"}'
        ']} '
        "(action_class is one of passive|active-scan|exploit|post-exploit).\n"
        "Return ONLY the JSON."
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
           remaining_count: int, scope_targets: list) -> AnalystDecision:
    user = (
        f"Engagement goal: {goal}\n"
        f"In-scope targets (you may ONLY target these): {', '.join(scope_targets)}\n"
        f"Objectives completed: {done_count}; still queued: {remaining_count}\n\n"
        f"Findings so far:\n{_render_findings(findings)}\n\n"
        "Decide: is the engagement goal met?\n"
        "The goal is ONLY met when concrete proof appears in the findings — a flag captured, "
        "credentials obtained, or privileged access gained. Enumerating services is NOT sufficient "
        "to declare done.\n\n"
        "If the goal is not yet met:\n"
        "- If findings reveal a service, port, or weakness, your NEXT objectives MUST be "
        "EXPLOITATION objectives (action_class: exploit or post-exploit) that act on those "
        "findings. Do NOT propose more scanning of a service that has already been enumerated.\n"
        "- Only propose additional recon (active-scan) for targets or services not yet explored.\n"
        "- Use ONLY in-scope targets from this list or specific hosts already discovered within "
        "them in the findings. NEVER invent or target any other IP/host.\n\n"
        "Do not repeat completed work.\n"
        'Reply EXACTLY: {"done": false, "reason": "why", "next_objectives": '
        '[{"objective": "exploit the identified SSH service to gain shell access", '
        '"target": "<in-scope-target>", "action_class": "exploit"}]}\n'
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
