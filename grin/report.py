"""The Reporter — pure Markdown rendering of a finished engagement, plus deterministic and
optional-LLM summaries. Read-only: no tools, no spine. The LLM summary degrades gracefully."""
import json
from pathlib import Path

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def deterministic_summary(result) -> str:
    n = len(result.findings)
    objs = len(result.objectives_run)
    blocked = len(result.paused)
    if n == 0:
        return f"No findings across {_plural(objs, 'objective')}; {blocked} blocked awaiting approval."
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    parts = [f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts[s]]
    return (f"{_plural(n, 'finding')} ({', '.join(parts)}) across {_plural(objs, 'objective')}; "
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


def attack_coverage(catalog, audit, findings) -> dict:
    """Map executed actions + findings onto ATT&CK technique ids via the catalog's tool->technique
    map. 'attempted' = a tool for the technique ran (allow in audit); 'succeeded' = a tool for the
    technique produced a finding. Returns {'attempted': [ids], 'succeeded': [ids], 'by_tactic': {...}}."""
    from grin.catalog import tool_to_techniques
    t2t = tool_to_techniques(catalog)
    id_to_tech = {t.id: t for t in catalog}

    def _ids_for_tool(tool):
        return t2t.get(tool, [])

    attempted, succeeded = [], []
    for rec in audit or []:
        if rec.get("decision") != "allow":
            continue
        for tid in _ids_for_tool(rec.get("tool", "")):
            if tid not in attempted:
                attempted.append(tid)
    for f in findings or []:
        for tid in _ids_for_tool(getattr(f, "tool", "")):
            if tid not in succeeded:
                succeeded.append(tid)
    by_tactic = {}
    for tid in attempted:
        tech = id_to_tech.get(tid)
        if tech:
            by_tactic.setdefault(tech.tactic, []).append(tid)
    return {"attempted": attempted, "succeeded": succeeded, "by_tactic": by_tactic}


def render_discovered(d) -> str:
    """A deterministic '## Discovered' section from a Discoveries (raw observed facts, not LLM
    findings). Returns '' when nothing was discovered."""
    if not d or (not d.hosts and not d.credentials and not d.flags):
        return ""
    lines = ["## Discovered", ""]
    for h in d.hosts:
        host = h.target or "(unattributed)"
        svcs = ", ".join(f"{s.port}/tcp {s.name}" for s in h.services) or "(no open ports)"
        lines.append(f"- **{host}**: {svcs}")
    if d.credentials:
        lines += ["", "### Credentials"]
        lines += [f"- `{c.value}` ({c.target or '?'} via {c.tool or '?'})" for c in d.credentials]
    if d.flags:
        lines += ["", "### Flags"]
        lines += [f"- `{f.value}`" for f in d.flags]
    return "\n".join(lines) + "\n"


def render_report(engagement, result, *, audit_summary: str, summary_text: str,
                  catalog=None, audit_records=None, discoveries=None) -> str:
    eng = engagement
    out = []
    out.append(f"# Grin Engagement Report — {eng.name}")
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
    _disc = render_discovered(discoveries) if discoveries is not None else ""
    if _disc:
        out.append(_disc.rstrip("\n"))
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
        other = [f for f in result.findings if f.severity not in SEVERITY_ORDER]
        if other:
            out.append("### other")
            for f in other:
                out.append(_finding_block(f))
            out.append("")
    out.append("## Secrets")
    if not getattr(result, "secrets", []):
        out.append("No secrets captured.")
    else:
        for s in result.secrets:
            out.append(f"- **[{s.label}]** {s.target}")
            out.append(f"  - value: {s.value}")
            out.append(f"  - tool: `{s.tool}`  command: `{s.command}`")
            if s.context:
                out.append(f"  - context: {s.context}")
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
    if catalog is not None:
        cov = attack_coverage(catalog, audit_records or [], result.findings)
        out.append("")
        out.append("## ATT&CK Coverage")
        if not cov["attempted"]:
            out.append("No techniques attempted.")
        else:
            id_to_name = {t.id: t.name for t in catalog}
            for tactic, ids in sorted(cov["by_tactic"].items()):
                out.append(f"- {tactic}:")
                for tid in ids:
                    mark = "succeeded" if tid in cov["succeeded"] else "attempted"
                    out.append(f"  - {tid} {id_to_name.get(tid, '')} ({mark})")
    return "\n".join(out)
