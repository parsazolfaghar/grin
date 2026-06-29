"""Engagement mode: CTF (the original flag-capture behavior) vs ASSESSMENT (enumerate and
report real vulnerabilities with evidence).

resolve_mode keeps the default CTF, so every existing engagement, lab, and test is unchanged.
Assessment is opt-in: an explicit `mode: assessment`, or a web-url target (where flag-capture
makes no sense). Any other/legacy mode value (e.g. own-lab) resolves to CTF behavior."""

ASSESSMENT = "assessment"
CTF = "ctf"


def resolve_mode(engagement_mode, target_type) -> str:
    m = str(engagement_mode or "").strip().lower()
    if m == ASSESSMENT:
        return ASSESSMENT
    if m == CTF:
        return CTF
    if str(target_type or "").strip().lower() == "web-url":
        return ASSESSMENT
    return CTF
