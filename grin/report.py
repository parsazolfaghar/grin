"""The Reporter — pure rendering of a finished engagement (Markdown, SARIF, HTML) plus
deterministic and optional-LLM summaries. Read-only: no tools, no spine. The LLM summary
degrades gracefully."""
import html as _html
import json
import re
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


# ---------------------------------------------------------------------------
# SARIF 2.1.0 — machine-readable output for CI / GitHub code-scanning. Closes the gap vs Swarm,
# and lets grin findings flow into the same dashboards as SAST/DAST tooling. Pure.
# ---------------------------------------------------------------------------

# SARIF has three levels; map pentest severity onto them. Unknown -> "note" (never over-state).
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def sarif_level(severity: str) -> str:
    return _SARIF_LEVEL.get((severity or "").strip().lower(), "note")


def _rule_id(severity: str, title: str) -> str:
    """Stable, slug-ish rule id from a finding's class. SARIF requires every result.ruleId to be
    defined in the driver's rules, so we derive both from the same function."""
    slug = re.sub(r"[^a-z0-9]+", "-", (title or "finding").strip().lower()).strip("-") or "finding"
    return f"grin/{(severity or 'info').strip().lower()}/{slug}"


def render_sarif(engagement, result, *, version: str = "0.1.0") -> str:
    """Render findings as a SARIF 2.1.0 document (JSON string). One run, one result per finding;
    each finding's target becomes the result location URI."""
    rules: dict[str, dict] = {}
    results = []
    for f in result.findings:
        rid = _rule_id(f.severity, f.title)
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": re.sub(r"\s+", "", f.title.title()) or "Finding",
                "shortDescription": {"text": f.title},
                "defaultConfiguration": {"level": sarif_level(f.severity)},
            }
        msg = f.title
        if f.evidence:
            msg += f" — {f.evidence}"
        results.append({
            "ruleId": rid,
            "level": sarif_level(f.severity),
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.target or "engagement"},
                },
            }],
            "properties": {
                "severity": f.severity,
                "tool": f.tool,
                "command": f.command,
                "recommendation": f.recommendation,
            },
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Grin",
                "informationUri": "https://github.com/parsazolfaghar/grin",
                "version": version,
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


# ---------------------------------------------------------------------------
# HTML — a standalone, shareable, self-contained report (no external assets). Pure. Everything
# from the engagement is HTML-escaped: a finding title/evidence is attacker-influenced text and
# must NEVER render as live markup in the report.
# ---------------------------------------------------------------------------

_SEV_COLOR = {"critical": "#b3001b", "high": "#d1495b", "medium": "#e3a008",
              "low": "#3a86ff", "info": "#6c757d"}

_HTML_CSS = """
:root{color-scheme:dark}
body{background:#0f1115;color:#e6e6e6;font:15px/1.55 ui-sans-serif,system-ui,-apple-system,sans-serif;
  max-width:880px;margin:0 auto;padding:2.5rem 1.25rem}
h1{font-size:1.7rem;letter-spacing:-.02em;margin:0 0 .25rem}
h2{font-size:1.15rem;border-bottom:1px solid #2a2e37;padding-bottom:.3rem;margin:2.2rem 0 1rem}
.meta{color:#8b919e;font-size:.85rem;margin-bottom:1.5rem}
.sum{background:#161922;border:1px solid #2a2e37;border-radius:10px;padding:1rem 1.15rem}
.f{background:#161922;border:1px solid #2a2e37;border-left-width:4px;border-radius:8px;
  padding:.85rem 1rem;margin:.7rem 0}
.f h3{margin:0 0 .35rem;font-size:1rem}
.badge{display:inline-block;font-size:.7rem;font-weight:600;text-transform:uppercase;
  letter-spacing:.04em;color:#fff;padding:.1rem .5rem;border-radius:4px;margin-right:.5rem}
.kv{color:#8b919e;font-size:.82rem;margin:.15rem 0}
code{background:#0b0d12;padding:.1rem .35rem;border-radius:4px;font-size:.82rem}
.none{color:#8b919e}
"""


def _esc(s) -> str:
    return _html.escape(str(s or ""))


def render_html(engagement, result, *, summary_text: str) -> str:
    eng = engagement
    p = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
         '<meta name="viewport" content="width=device-width,initial-scale=1">',
         f"<title>Grin Report — {_esc(eng.name)}</title>",
         f"<style>{_HTML_CSS}</style></head><body>"]
    p.append(f"<h1>Grin Engagement Report — {_esc(eng.name)}</h1>")
    p.append(f'<div class="meta">Engagement <code>{_esc(eng.id)}</code> · '
             f"status {_esc(result.status)} · "
             f"{len(result.objectives_run)} objective(s) · "
             f"scope: {_esc(', '.join(eng.scope.include) or '(none)')}</div>")
    p.append("<h2>Executive summary</h2>")
    p.append(f'<div class="sum">{_esc(summary_text)}</div>')
    p.append("<h2>Findings</h2>")
    if not result.findings:
        p.append('<p class="none">No findings.</p>')
    else:
        ordered = sorted(result.findings,
                         key=lambda f: SEVERITY_ORDER.index(f.severity)
                         if f.severity in SEVERITY_ORDER else len(SEVERITY_ORDER))
        for f in ordered:
            color = _SEV_COLOR.get(f.severity, "#6c757d")
            p.append(f'<div class="f" style="border-left-color:{color}">')
            p.append(f'<h3><span class="badge" style="background:{color}">{_esc(f.severity)}</span>'
                     f"{_esc(f.title)}</h3>")
            p.append(f'<div class="kv">Target: {_esc(f.target)}</div>')
            if f.tool or f.command:
                p.append(f'<div class="kv">Tool: <code>{_esc(f.tool)}</code> · '
                         f"Command: <code>{_esc(f.command)}</code></div>")
            if f.evidence:
                p.append(f'<div class="kv">Evidence: {_esc(f.evidence)}</div>')
            if f.recommendation:
                p.append(f'<div class="kv">Recommendation: {_esc(f.recommendation)}</div>')
            p.append("</div>")
    p.append("</body></html>")
    return "\n".join(p)
