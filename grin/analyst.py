"""The Analyst — Grin's pure-LLM planning brain. It never touches tools or the spine; it only
reasons over findings to plan objectives. initial_plan seeds the queue; replan chases leads and
decides when the engagement goal is met. Tolerant JSON parsing, fail-soft on a miss."""
from dataclasses import dataclass

from grin.objective import Objective
from grin.classes import ACTION_CLASSES
from grin.jsonextract import extract_json
from grin.mode import ASSESSMENT, CTF

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


def initial_plan(client, model: str, goal: str, scope_targets, seeds, mode: str = CTF) -> list:
    if mode == ASSESSMENT:
        user = (
            f"Engagement goal: {goal}\n"
            f"In-scope targets (patterns): {', '.join(scope_targets)}\n"
            f"Operator seed targets: {', '.join(seeds) if seeds else '(none)'}\n\n"
            "Produce the FIRST short list of objectives for a security ASSESSMENT: enumerate the "
            "application surface and find REAL vulnerabilities to REPORT — there is NO flag to "
            "capture. For THIS engagement, focus on BROKEN ACCESS CONTROL. Plan objectives to "
            "(1) enumerate the app, and (2) run the `bac-probe` helper to find resources served "
            "WITHOUT authentication. AND — if the goal supplies CREDENTIALS for two users — also "
            "(3) test for IDOR (cross-user object access) with the `idor-probe` helper. Report "
            "everything as findings. Do NOT plan loot, flag, or credential-theft objectives.\n"
            "Reply EXACTLY with a JSON array of objectives:\n"
            '{"objectives": ['
            '{"objective": "enumerate the web application surface and endpoints", '
            '"target": "<in-scope-target>", "action_class": "active-scan"}, '
            '{"objective": "test for broken access control with bac-probe (resources served '
            'without authentication)", "target": "<in-scope-target>", "action_class": "active-scan"}, '
            '{"objective": "if credentials are provided, test for IDOR with idor-probe (one user '
            'reading another user\'s objects)", "target": "<in-scope-target>", "action_class": "exploit"}'
            ']} '
            "(action_class is one of passive|active-scan|exploit|post-exploit).\n"
            "Return ONLY the JSON."
        )
        data = _extract_json(client.generate(model=model, system=PLANNER_SYSTEM, prompt=user,
                                             temperature=0.3))
        return _parse_objectives(data.get("objectives", [])) if isinstance(data, dict) else []
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


def _compact_value(value: str, limit: int = 60) -> str:
    """Keep the planner prompt readable: collapse a multi-line/long secret value (e.g. a PEM private
    key) to a one-line summary. The full value is still stored in loot — the planner only needs to
    know the secret exists, not its raw bytes."""
    v = (value or "").strip()
    if "\n" in v or len(v) > limit:
        head = v.splitlines()[0][:limit]
        return f"{head} …[{len(v)} chars]"
    return v


def _render_secrets(secrets) -> str:
    if not secrets:
        return "(none captured yet)"
    return "\n".join(
        f"- [{s.label}] {_compact_value(s.value)} ({s.target}) via {s.tool}" for s in secrets)


def replan(client, model: str, goal: str, findings, done_count: int,
           remaining_count: int, scope_targets: list, secrets=None,
           mode: str = CTF) -> AnalystDecision:
    secrets = secrets or []
    if mode == ASSESSMENT:
        user = (
            f"Engagement goal: {goal}\n"
            f"In-scope targets (you may ONLY target these): {', '.join(scope_targets)}\n"
            f"Objectives completed: {done_count}; still queued: {remaining_count}\n\n"
            f"Findings so far:\n{_render_findings(findings)}\n\n"
            "Decide: is the ASSESSMENT goal met?\n"
            "The goal IS met once you have enumerated the reachable surface and the broken-access-"
            "control findings are reported (a resource served WITHOUT authentication is a finding; "
            "they appear under Findings above). If enumeration is done and findings are reported, "
            "reply done=true. Reporting ZERO findings after thorough enumeration is ALSO a valid "
            "done — never invent one. Do NOT plan loot, flag, or credential-theft objectives.\n"
            "If enumeration is NOT yet complete, propose active-scan objectives (e.g. run "
            "`bac-probe` on paths not yet checked) against in-scope targets only.\n\n"
            "Do not repeat completed work.\n"
            'Reply EXACTLY: {"done": false, "reason": "why", "next_objectives": '
            '[{"objective": "run bac-probe to test untested paths for missing auth", '
            '"target": "<in-scope-target>", "action_class": "active-scan"}]}\n'
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
    user = (
        f"Engagement goal: {goal}\n"
        f"In-scope targets (you may ONLY target these): {', '.join(scope_targets)}\n"
        f"Objectives completed: {done_count}; still queued: {remaining_count}\n\n"
        f"Findings so far:\n{_render_findings(findings)}\n\n"
        f"Secrets/flags captured so far:\n{_render_secrets(secrets)}\n\n"
        "Decide: is the engagement goal met?\n"
        "The goal IS met once concrete proof has been obtained — a flag captured, credentials "
        "obtained, or privileged access gained. Such proof appears under Findings OR under "
        "Secrets/flags captured above; if the goal asked for a flag and one is listed there, you "
        "MUST reply done=true. Enumerating services is NOT sufficient to declare done.\n\n"
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
