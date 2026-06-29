"""A Finding — the unit the SP4 Reporter will consume. Severity is fail-soft: a bad label
is normalized to 'info', never dropped (a finding is never lost over a labeling glitch)."""
from dataclasses import dataclass

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class Finding:
    title: str
    target: str
    severity: str
    evidence: str
    tool: str
    command: str
    recommendation: str = ""
    # Optional, defaulted so legacy findings (and asdict/Finding(**) round-trips) keep working.
    # Populated by the assessment pipeline (SP2+); the assessbench scorer uses them when present.
    vuln_class: str = ""
    location: str = ""


def normalize_severity(s) -> str:
    s = str(s or "").strip().lower()
    return s if s in SEVERITIES else "info"
