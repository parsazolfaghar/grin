"""Prompt construction + tolerant reply parsing for the Executor loop. Free-text prompts
(no JSON mode) + JSON-then-Markdown parsing, per Sensei's experience with local GGUF models."""
import json
import re
from dataclasses import dataclass

from grin.finding import Finding, normalize_severity

SYSTEM = (
    "You are Grin's Executor, an autonomous penetration-testing agent operating under an "
    "explicit, human-authorized, scope-bound engagement. You accomplish ONE objective by "
    "driving Kali/BlackArch tools. Every action you propose is checked by a scope/ROE "
    "gatekeeper before it runs; out-of-scope or disallowed actions are refused and you must "
    "adapt. Propose the SINGLE next action, or finish with findings. Reply with ONE JSON "
    "object and nothing else."
)


def build_step_prompt(objective: str, target: str, journal, allowed_classes) -> tuple[str, str]:
    history = journal.render_history()
    user = (
        f"Objective: {objective}\n"
        f"Authorized target: {target}\n"
        f"Permitted action classes (ROE): {', '.join(allowed_classes)}\n\n"
        f"History so far:\n{history}\n\n"
        "Decide the SINGLE next action, or finish if the objective is met.\n"
        'To act, reply EXACTLY: {"action": {"tool": "nmap", "command": "nmap -sV '
        f'{target}", "target": "{target}", "declared_class": "active-scan", '
        '"why": "short reason"}}\n'
        'To finish, reply EXACTLY: {"done": true, "findings": [{"title": "...", '
        '"severity": "info|low|medium|high|critical", "evidence": "...", "tool": "...", '
        '"command": "...", "recommendation": "..."}]}\n'
        "Return ONLY the JSON object."
    )
    return SYSTEM, user


@dataclass
class StepDecision:
    kind: str                         # action | done | parse_miss
    action: dict | None = None
    findings: list | None = None


def _extract_json(raw: str):
    try:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        return json.loads(m.group(0)) if m else None
    except (json.JSONDecodeError, AttributeError, TypeError):
        return None


def _parse_findings(items, default_target) -> list:
    out = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        title = str(it.get("title", "")).strip()
        if not title:
            continue
        out.append(Finding(
            title=title,
            target=str(it.get("target") or default_target).strip(),
            severity=normalize_severity(it.get("severity")),
            evidence=str(it.get("evidence", "")).strip(),
            tool=str(it.get("tool", "")).strip(),
            command=str(it.get("command", "")).strip(),
            recommendation=str(it.get("recommendation", "")).strip(),
        ))
    return out


_CMD_RE = re.compile(r"(?im)^\s*[#>*\-\s]*\**\s*command\s*\**\s*:\s*(.+)$")


def parse_step(raw: str, default_target: str) -> StepDecision:
    data = _extract_json(raw)
    if isinstance(data, dict):
        act = data.get("action")
        if isinstance(act, dict) and str(act.get("tool", "")).strip() \
                and str(act.get("command", "")).strip():
            dc = act.get("declared_class")
            return StepDecision("action", action={
                "tool": str(act["tool"]).strip(),
                "command": str(act["command"]).strip(),
                "target": str(act.get("target") or default_target).strip(),
                "declared_class": str(dc).strip() if dc else None,
                "why": str(act.get("why", "")).strip(),
            })
        if data.get("done") or "findings" in data:
            return StepDecision("done", findings=_parse_findings(data.get("findings", []),
                                                                 default_target))
    # Markdown fallback: a "Command:" line -> an action (tool = first token).
    m = _CMD_RE.search(raw or "")
    if m:
        command = m.group(1).strip().strip("`").strip()
        if command:
            return StepDecision("action", action={
                "tool": command.split()[0], "command": command,
                "target": default_target, "declared_class": None, "why": "",
            })
    return StepDecision("parse_miss")
