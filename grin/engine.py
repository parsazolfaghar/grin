"""The general engine pipeline: run a queue of candidates through their verifiers and emit a
Finding for every CONFIRMED verdict — nothing else.

This is the join the architecture is built around: recon produces Candidates, the harness builds
one Transport (per-role sessions), and assess() runs verify() over the queue. REJECTED and
INCONCLUSIVE never become findings — code, not the LLM, decides what is real."""
import re

from grin.verify import verify, Candidate, Transport, CONFIRMED
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


def _urllib_request():
    import json as _json
    import urllib.request

    def request(method, url, json=None, headers=None):
        h = dict(headers or {})
        data = None
        if json is not None:
            data = _json.dumps(json).encode()
            h["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        try:
            r = urllib.request.urlopen(req, timeout=8)
            return r.status, r.read(262144).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, ""
        except Exception:
            return 0, ""
    return request


def build_transport(request, base_url, credentials=None, login_path="/rest/user/login"):
    """Build the Transport (per-role request surface) from a request fn + optional credentials.

    The harness owns auth + resource discovery: it logs in the first two credentials as attacker
    and victim, and returns the victim's owned resource id so the caller can form the IDOR
    candidate. Returns (transport, victim_resource_id)."""
    by_role = {"anon": lambda u: request("GET", u)}
    victim_id = None
    creds = list(credentials or [])
    if len(creds) >= 2:
        from grin.tools.idor_probe import login_session
        post = lambda u, b: request("POST", u, json=b)   # noqa: E731
        ta, _ = login_session(base_url, creds[0]["email"], creds[0]["password"], post, login_path)
        tb, victim_id = login_session(base_url, creds[1]["email"], creds[1]["password"],
                                      post, login_path)
        if ta:
            by_role["attacker"] = lambda u, t=ta: request("GET", u,
                                                          headers={"Authorization": "Bearer " + t})
        if tb:
            by_role["victim"] = lambda u, t=tb: request("GET", u,
                                                        headers={"Authorization": "Bearer " + t})
    return Transport(request=request, by_role=by_role), victim_id


def run_general(base_url, credentials=None, *, request=None,
                resource_template="/rest/basket/{id}", login_path="/rest/user/login", target=""):
    """End-to-end: build the transport (sessions), recon the surface, resolve the session-coupled
    IDOR candidate, and assess everything. Deterministic; the LLM is not in this path."""
    request = request or _urllib_request()
    transport, victim_id = build_transport(request, base_url, credentials, login_path)
    candidates = recon(base_url, transport.by_role["anon"], login_path=login_path)
    if victim_id is not None and "attacker" in transport.by_role and "victim" in transport.by_role:
        url = base_url.rstrip("/") + resource_template.replace("{id}", str(victim_id))
        candidates.append(Candidate("idor", resource_template, url))
    return assess(candidates, transport, target=target or base_url)


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
