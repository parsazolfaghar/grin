"""The Medic — Grin's rescue/self-audit agent. Paged by the Orchestrator when an engagement
stalls. Reads the engagement's own evidence (findings, secrets, recent command trail) and either
RECOVERS (proposes materially different objectives) or CONCLUDES with a plain-language diagnosis.
Like the Analyst it ONLY plans — never runs tools or edits code. Tolerant JSON parsing, fail-soft."""
from dataclasses import dataclass, field

from grin.analyst import _parse_objectives, _render_findings, _render_secrets
from grin.jsonextract import extract_json

MEDIC_SYSTEM = (
    "You are Grin's Medic — an incident responder paged when an authorized, scope-bound "
    "penetration test has STALLED (several objectives with no new progress). You are given the "
    "goal, what has been found, and the recent command trail. Diagnose what was achieved, what is "
    "blocking, and what has NOT been tried. If a concrete, materially different next step exists, "
    "propose it; otherwise conclude with a precise diagnosis. A separate Executor runs tools under "
    "a fail-closed gatekeeper; you only plan, in scope. Reply with ONE JSON object and nothing else.\n"
    "Common stuck-states and the CONCRETE recovery to propose (match the trail to one):\n"
    "- RCE as a low-priv user but the flag is root-owned / unreadable: do NOT keep re-reading it. "
    "Escalate — enumerate SUID (`find / -perm -4000 -type f`), inspect any custom binary with "
    "`strings`, and PATH-hijack a relative call (e.g. one that runs `uptime`). PREFER the "
    "`suid-hijack` helper, which does this whole privesc automatically through the web RCE: "
    "`suid-hijack --url http://<t>/ --param name --mode ssti --flag /root/flag.txt`.\n"
    "- SSH'd / pivoted into a host but no flag yet: the flag is that USER's home — `cat ~/flag.txt` / "
    "`cat /home/<user>/flag.txt` — not `/flag.txt` and not a broad `find` that returns /sys noise.\n"
    "- Stole an SSH key but haven't used it (or are brute-forcing passwords on the vault instead of "
    "using the key): use the `ssh-loot` helper — it cracks the passphrase, decrypts, tries the likely "
    "users (incl. one named in the README) and reads the flag from home: "
    "`ssh-loot --host <vault> --key /tmp/loot/id_rsa --readme '<readme>'`.\n"
    "- Injection returns only normal output (no `uid=`): the separator is filtered — cycle "
    "`;`/`|`/`&&`/`$()`/newline.\n"
    "- Multi-step web exploit not landing by hand: use the `web-rce` helper (it handles all encoding)."
)


MEDIC_PATCH_SYSTEM = (
    "You are Grin's Medic in PATCH-PROPOSAL mode. The engagement hit a wall that looks like a "
    "MISSING CAPABILITY in Grin itself (e.g. it saw loot in tool output but had no extractor for it, "
    "or a foothold type with no helper). Draft a concrete code-change PROPOSAL for a HUMAN to review "
    "— you do NOT apply it. Grin's extension points: deterministic loot extractors in "
    "`grin/extractors.py`; self-contained runner helpers in `grin/tools/` (e.g. web-rce/ssh-loot/"
    "suid-hijack); executor tradecraft in `grin/prompts.py`; the Medic playbooks in `grin/medic.py`. "
    "Reply in markdown: the missing capability, the target file, and a concrete code/diff snippet. "
    "Keep it minimal and testable. This is a SUGGESTION ONLY."
)


@dataclass
class MedicDecision:
    action: str                                       # "recover" | "conclude"
    objectives: list = field(default_factory=list)    # list[Objective] when recover
    diagnosis: str = ""                               # plain-language reason when conclude
    patch: str = ""                                   # human-review patch proposal (opt-in, conclude)


def propose_patch(client, model, *, diagnosis, goal) -> str:
    """Draft a code-patch PROPOSAL (markdown) addressing the capability wall in the diagnosis. For
    HUMAN review only — never auto-applied. Fail-soft: returns '' on error."""
    try:
        user = (f"Engagement goal: {goal}\n"
                f"Diagnosis of the wall Grin hit:\n{diagnosis}\n\n"
                "Draft the minimal code-change proposal (target file + code/diff) that would give "
                "Grin the missing capability, so it wouldn't hit this wall again. Suggestion only.")
        return client.generate(model=model, system=MEDIC_PATCH_SYSTEM, prompt=user,
                               temperature=0.2) or ""
    except Exception:
        return ""


def _render_trail(recent_steps) -> str:
    if not recent_steps:
        return "(no command trail)"
    lines = []
    for s in recent_steps[-40:]:
        out = (s.get("output") or "").replace("\n", " ")[:160]
        ex = ",".join(s.get("extracted") or [])
        lines.append(f"- [{(s.get('objective') or '')[:30]}] {(s.get('command') or '')[:80]} "
                     f"(exit {s.get('exit_code')}){(' => ' + ex) if ex else ''} | {out}")
    return "\n".join(lines)


def triage(client, model, *, goal, findings, secrets, tried_objectives, recent_steps,
           scope_targets, max_new: int = 3, propose_patches: bool = False) -> MedicDecision:
    """One rescue pass. Returns recover (new objectives) or conclude (diagnosis). Fail-soft:
    on an unparseable reply, concludes rather than raising. When propose_patches is set, a CONCLUDE
    also carries a human-review code-patch proposal (the diagnosis points at a capability wall)."""
    def _concl(diag: str) -> MedicDecision:
        patch = propose_patch(client, model, diagnosis=diag, goal=goal) if propose_patches else ""
        return MedicDecision(action="conclude", diagnosis=diag, patch=patch)

    tried = "\n".join(f"- {o.objective} @ {o.target}" for o in tried_objectives) or "(none)"
    user = (
        f"Engagement goal: {goal}\n"
        f"In-scope targets: {', '.join(scope_targets)}\n\n"
        f"Findings so far:\n{_render_findings(findings)}\n\n"
        f"Secrets/loot captured:\n{_render_secrets(secrets)}\n\n"
        f"Objectives already TRIED (do not repeat):\n{tried}\n\n"
        f"Recent command trail:\n{_render_trail(recent_steps)}\n\n"
        "The run has stalled. State briefly what was achieved and what is blocking. Then either "
        f"propose UP TO {max_new} NEW, materially different objectives not already tried (e.g. if "
        "code execution was achieved but the flag was never read, propose reading it; if a foothold "
        "exists but no privesc was attempted, propose escalation), OR if no new approach exists, "
        "conclude.\n"
        'Reply EXACTLY with ONE JSON object: {"action": "recover", "objectives": '
        '[{"objective": "...", "target": "<in-scope>", "action_class": "exploit"}]} '
        'OR {"action": "conclude", "diagnosis": "<achieved, where blocked, and why>"}.\n'
        "Return ONLY the JSON."
    )
    data = extract_json(client.generate(model=model, system=MEDIC_SYSTEM, prompt=user,
                                        temperature=0.3),
                        want=("action", "objectives", "diagnosis"))
    if not isinstance(data, dict):
        return _concl("Medic could not parse a rescue plan; engagement stalled.")
    action = str(data.get("action", "")).strip().lower()
    if action == "recover":
        objs = _parse_objectives(data.get("objectives", []))[:max_new]
        tried_keys = {(o.objective, o.target) for o in tried_objectives}
        objs = [o for o in objs if (o.objective, o.target) not in tried_keys]
        if objs:
            return MedicDecision(action="recover", objectives=objs)
        return _concl(str(data.get("diagnosis", "")) or "No new tactic available; stalled.")
    return _concl(str(data.get("diagnosis", "")) or "Engagement stalled.")
