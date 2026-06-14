"""Honeypot / trap detector (roadmap R1) — ADVISORY ONLY.

Scores how likely the engagement is looking at a decoy, from two deterministic signal families:
 - known honeypot fingerprints in service banners / finding evidence (Cowrie, Kippo, Dionaea, ...),
 - implausibility heuristics (one host exposing an absurd number of "open" services).

It NEVER blocks or removes capability (per the roadmap guiding principle): it only flags, so the
operator can decide. No spine/execution involvement — pure read-only analysis of findings + audit.
"""
from dataclasses import dataclass, field

# Substrings that strongly indicate a honeypot when seen in a banner / finding evidence.
HONEYPOT_FINGERPRINTS = [
    "cowrie", "kippo", "dionaea", "honeyd", "nepenthes", "glastopf", "conpot", "t-pot",
    "tpot", "amun", "kfsensor", "honeytrap", "honeypot", "mhn", "thug", "shockpot",
]

OPEN_HINTS = ("open", "/tcp", "/udp", "tcp open", "port ")


@dataclass(frozen=True)
class TrapAssessment:
    score: int                       # 0-100 honeypot likelihood
    suspected: bool                  # score >= threshold
    signals: list = field(default_factory=list)
    detail: str = ""


def _finding_blob(f) -> str:
    parts = [getattr(f, "title", ""), getattr(f, "evidence", ""), getattr(f, "tool", ""),
             getattr(f, "command", "")]
    return " ".join(str(p) for p in parts).lower()


def assess(findings, audit_lines=None, *, open_port_threshold: int = 12,
           threshold: int = 40) -> TrapAssessment:
    """findings: list[Finding]; audit_lines: optional list[dict] (the JSONL audit records)."""
    signals = []
    score = 0

    haystacks = [_finding_blob(f) for f in (findings or [])]
    for a in (audit_lines or []):
        haystacks.append(f"{a.get('command', '')} {a.get('tool', '')}".lower())
    joined = " \n".join(haystacks)

    for fp in HONEYPOT_FINGERPRINTS:
        if fp in joined:
            signals.append(f"honeypot fingerprint '{fp}'")
            score += 50

    # implausibility: a single target exposing an absurd number of "open" services
    per_target = {}
    for f in (findings or []):
        blob = _finding_blob(f)
        if any(h in blob for h in OPEN_HINTS):
            tgt = str(getattr(f, "target", "")) or "?"
            per_target[tgt] = per_target.get(tgt, 0) + 1
    for tgt, n in per_target.items():
        if n >= open_port_threshold:
            signals.append(f"{n} 'open' findings on {tgt} (implausibly many)")
            score += 30

    score = min(100, score)
    suspected = score >= threshold
    if suspected:
        detail = "SUSPECTED honeypot/decoy — " + "; ".join(signals)
    elif signals:
        detail = "weak trap signals (below threshold) — " + "; ".join(signals)
    else:
        detail = "no honeypot signals detected"
    return TrapAssessment(score=score, suspected=suspected, signals=signals, detail=detail)
