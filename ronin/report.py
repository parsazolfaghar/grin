"""The Reporter — pure Markdown rendering of a finished engagement, plus deterministic and
optional-LLM summaries. Read-only: no tools, no spine. The LLM summary degrades gracefully."""
import json
from pathlib import Path

from ronin.finding import SEVERITIES  # noqa: F401 — imported for vocabulary parity

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def deterministic_summary(result) -> str:
    n = len(result.findings)
    objs = len(result.objectives_run)
    blocked = len(result.paused)
    if n == 0:
        return f"No findings across {objs} objectives; {blocked} blocked awaiting approval."
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    parts = [f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts[s]]
    return (f"{n} findings ({', '.join(parts)}) across {objs} objectives; "
            f"{blocked} blocked awaiting approval.")


def summarize_audit(audit_log_path: str) -> str:
    p = Path(audit_log_path)
    if not p.exists():
        return "(no audit log)"
    allow = refuse = 0
    for line in p.read_text().splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("decision") == "allow":
            allow += 1
        elif rec.get("decision") == "refuse":
            refuse += 1
    return f"{allow + refuse} actions logged: {allow} allowed, {refuse} refused."


def llm_summary(client, model: str, result) -> str:
    """Optional narrative exec summary; falls back to deterministic on any failure."""
    fallback = deterministic_summary(result)
    if not client.is_up():
        return fallback
    lines = "\n".join(f"- [{f.severity}] {f.title} ({f.target})" for f in result.findings) \
        or "(no findings)"
    prompt = (
        "Write a 2-3 sentence executive summary of this authorized penetration test for a "
        f"client report. Findings:\n{lines}\n\nReturn only the summary prose."
    )
    try:
        reply = client.generate(model=model, system="You write concise pentest report summaries.",
                                prompt=prompt, temperature=0.3)
    except Exception:        # noqa: BLE001 - never let the summary break the report
        return fallback
    reply = (reply or "").strip()
    return reply or fallback


def _finding_block(f) -> str:
    rec = f.recommendation.strip() or "—"
    return (f"- **{f.title}** — {f.target}\n"
            f"  - Tool: `{f.tool}`\n"
            f"  - Command: `{f.command}`\n"
            f"  - Evidence: {f.evidence}\n"
            f"  - Recommendation: {rec}")


def render_report(engagement, result, *, audit_summary: str, summary_text: str) -> str:
    eng = engagement
    out = []
    out.append(f"# Ronin Engagement Report — {eng.name}")
    out.append("")
    out.append(f"- Engagement: `{eng.id}`")
    out.append(f"- Mode: {eng.mode}")
    out.append(f"- Status: {result.status}")
    out.append(f"- Scope (in): {', '.join(eng.scope.include) or '(none)'}")
    out.append(f"- Scope (exclude): {', '.join(eng.scope.exclude) or '(none)'}")
    out.append(f"- Objectives run: {len(result.objectives_run)}")
    out.append("")
    out.append("## Executive summary")
    out.append(summary_text)
    out.append("")
    out.append("## Findings")
    if not result.findings:
        out.append("No findings.")
    else:
        for sev in SEVERITY_ORDER:
            group = [f for f in result.findings if f.severity == sev]
            if not group:
                continue
            out.append(f"### {sev}")
            for f in group:
                out.append(_finding_block(f))
            out.append("")
    out.append("## Methodology")
    out.append("Objectives run:")
    for o in result.objectives_run:
        out.append(f"- {o.objective} ({o.target})")
    reasons = [e.get("reason", "") for e in result.plan_log
               if e.get("kind") == "replan" and e.get("reason")]
    if reasons:
        out.append("")
        out.append("Analyst reasoning:")
        for r in reasons:
            out.append(f"- {r}")
    out.append("")
    out.append("## Blocked / awaiting approval")
    if not result.paused:
        out.append("None.")
    else:
        for p in result.paused:
            o = p["objective"]
            out.append(f"- {o.objective} on {o.target} — pending `{p.get('pending_id')}`")
    out.append("")
    out.append("## Appendix: audit trail")
    out.append(audit_summary)
    out.append("")
    return "\n".join(out)
