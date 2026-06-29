"""The general engine pipeline: run a queue of candidates through their verifiers and emit a
Finding for every CONFIRMED verdict — nothing else.

This is the join the architecture is built around: recon produces Candidates, the harness builds
one Transport (per-role sessions), and assess() runs verify() over the queue. REJECTED and
INCONCLUSIVE never become findings — code, not the LLM, decides what is real."""
import re

from grin.verify import verify, Candidate, CONFIRMED
from grin.finding import Finding

# Common injectable param names to try even when not linked on the page (the params reading the
# HTML never reveals). Combined with form-input names discovered in the body.
_COMMON_PARAMS = ("q", "search", "name", "id", "query", "s", "keyword", "page", "title", "message")
_INPUT_NAME_RE = re.compile(r'name=["\']([A-Za-z0-9_\-]+)["\']')


def _extract_params(body: str):
    found = set(_INPUT_NAME_RE.findall(body or ""))
    found.update(_COMMON_PARAMS)
    return sorted(found)


def recon(base_url, fetch, login_path="/rest/user/login"):
    """Minimal surface graph -> candidate queue. Deterministic; never depends on the LLM.

    fetch(url) -> (status, body). Produces:
      - BAC candidates for a known sensitive-path list (baseline = root, for the SPA-shell diff)
      - a SQLi candidate at the login endpoint
      - SSTI candidates for params discovered on the landing page + a common-param list
    (IDOR candidates are session-coupled — resolved by the harness that owns the per-role sessions.)"""
    from grin.tools.bac_probe import DEFAULT_PATHS
    base = base_url.rstrip("/")
    candidates = []
    for path in DEFAULT_PATHS:
        candidates.append(Candidate("broken-access-control", path, base + path,
                                    oracle={"baseline_url": base + "/"}))
    candidates.append(Candidate("sql-injection", login_path, base + login_path,
                                method="POST", inject_field="email"))
    try:
        _status, body = fetch(base + "/")
    except Exception:
        body = ""
    for param in _extract_params(body):
        candidates.append(Candidate("ssti", f"/ (param {param})", base + "/", inject_field=param))
    return candidates

# Per-class severity for the emitted finding. Conservative, overridable later by a CVSS pass.
_SEVERITY = {
    "sql-injection": "critical",
    "ssti": "critical",
    "idor": "high",
    "auth-bypass": "high",
    "broken-access-control": "medium",
    "ssrf": "high",
    "path-traversal": "high",
}


def assess(candidates, transport, target: str = ""):
    """Verify every candidate; return a Finding for each CONFIRMED verdict (in input order)."""
    findings = []
    for c in candidates:
        verdict = verify(c, transport)
        if verdict.status != CONFIRMED:
            continue
        findings.append(Finding(
            title=f"{verdict.vuln_class}: {verdict.location}",
            target=target or c.url,
            severity=_SEVERITY.get(verdict.vuln_class, "medium"),
            evidence=verdict.evidence,
            tool="grin-verify",
            command=f"verify[{verdict.vuln_class}] {c.url}",
            recommendation="",
            vuln_class=verdict.vuln_class,
            location=verdict.location,
        ))
    return findings
