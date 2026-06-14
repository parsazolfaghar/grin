"""Render a BenchReport: machine-readable JSON + a plain-text ranked listing with a RECOMMENDED
PIN per role and a copy-paste engage line. No markdown tables (fixed-width text)."""
import json


def to_json(report) -> str:
    return json.dumps({
        "models": report.models,
        "roles": report.roles,
        "recommended_pins": report.recommended_pins(),
        "role_results": [
            {"model": r.model, "role": r.role, "score": r.score, "refused": r.refused,
             "refused_count": r.refused_count, "n_cases": r.n_cases, "latency_s": r.latency_s,
             "cases": [{"case": c.case_name, "score": c.score, "refused": c.refused,
                        "latency_s": c.latency_s, "breakdown": c.breakdown, "error": c.error}
                       for c in r.cases]}
            for r in report.role_results],
    }, indent=2)


def to_text(report) -> str:
    lines = ["GRIN MODEL BENCHMARK", "=" * 60, ""]
    if any(">>" in m for m in report.models):
        lines += ["(rows shown as advisor>>driver are two-model strategies — BENCH-ONLY, "
                  "not yet a valid --exploit-model value)", ""]
    for role in report.roles:
        lines.append(f"[ {role.upper()} ]")
        ranked = sorted([r for r in report.role_results if r.role == role],
                        key=lambda r: r.score, reverse=True)
        lines.append(f"  {'MODEL':<52}{'SCORE':>7}  {'LAT(s)':>7}  REFUSED")
        for r in ranked:
            ref = f"{r.refused_count}/{r.n_cases}" if r.refused_count else "-"
            lines.append(f"  {r.model:<52}{r.score:>7.1f}  {r.latency_s:>7.2f}  {ref}")
        lines.append("")
    pins = report.recommended_pins()
    lines.append("RECOMMENDED PINS")
    lines.append("-" * 60)
    for role, model in pins.items():
        lines.append(f"  {role:<10} -> {model}")
    flag = {"planner": "--planner-model", "recon": "--recon-model", "exploit": "--exploit-model"}
    parts = [f"{flag[r]} {m}" for r, m in pins.items() if r in flag]
    if parts:
        lines += ["", "  grin engage <eng> --goal \"...\" " + " ".join(parts)]
    return "\n".join(lines)
