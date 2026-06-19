"""CI gate — the deterministic pass/fail decision that turns an engagement result into a build
verdict + exit code. This is Strix's CI mode in grin's idiom: run grin headless against a
deploy/staging target in a pipeline and fail the build when the pentest surfaces a finding at or
above a chosen severity. Pure: no tools, no spine, no I/O."""
from grin.report import SEVERITY_ORDER  # ("critical","high","medium","low","info"), most->least

# Exit codes: 0 = gate passed; 2 = offending findings present (build should fail). 1 stays reserved
# for operational errors (bad engagement, model down) handled by the CLI, never for a clean fail.
EXIT_PASS = 0
EXIT_FAIL = 2


def _rank(severity: str) -> int | None:
    """Index into SEVERITY_ORDER (0 = most severe), or None for an unknown severity."""
    sev = (severity or "").strip().lower()
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else None


def meets_threshold(severity: str, fail_on: str) -> bool:
    """True when `severity` is at least as severe as `fail_on`. Unknown severities never trip the
    gate (fail-safe: don't fail a build on an unclassifiable finding)."""
    s, t = _rank(severity), _rank(fail_on)
    if s is None or t is None:
        return False
    return s <= t   # lower index == more severe


def ci_gate(findings, *, fail_on: str = "high"):
    """Decide the build verdict. Returns (exit_code, offending_findings, summary).
    offending = the findings at/above `fail_on`; exit_code is EXIT_FAIL iff any exist."""
    offending = [f for f in (findings or []) if meets_threshold(f.severity, fail_on)]
    if offending:
        counts: dict[str, int] = {}
        for f in offending:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        parts = [f"{counts[s]} {s}" for s in SEVERITY_ORDER if s in counts]
        summary = (f"FAIL: {len(offending)} finding(s) at or above '{fail_on}' "
                   f"({', '.join(parts)}).")
        return EXIT_FAIL, offending, summary
    total = len(findings or [])
    summary = (f"pass: no findings at or above '{fail_on}'"
               + (f" ({total} lower-severity finding(s))." if total else "."))
    return EXIT_PASS, [], summary
