"""The general engine pipeline: run a queue of candidates through their verifiers and emit a
Finding for every CONFIRMED verdict — nothing else.

This is the join the architecture is built around: recon produces Candidates, the harness builds
one Transport (per-role sessions), and assess() runs verify() over the queue. REJECTED and
INCONCLUSIVE never become findings — code, not the LLM, decides what is real."""
import re
import time

from grin.verify import verify, Candidate, Transport, CONFIRMED
from grin.finding import Finding

# Common injectable param names to try even when not linked on the page (the params reading the
# HTML never reveals). Combined with form-input names discovered in the body.
_COMMON_PARAMS = ("q", "search", "name", "id", "query", "s", "keyword", "page", "title", "message")
_INPUT_NAME_RE = re.compile(r'name\s*=\s*["\']?([A-Za-z0-9_\-]+)')   # quoted OR unquoted attribute
# Param names worth an SSRF probe — clearly URL-bearing. Excludes open-redirect/LFI-prone names
# (redirect/next/page/file) to keep the SSRF candidate set focused.
_URL_PARAM_RE = re.compile(
    r"^(url|uri|link|src|source|dest|destination|target|callback|webhook|proxy|feed|fetch|load|"
    r"remote|site|image_url|avatar_url|return_url|redirect_uri|u|endpoint)$", re.I)
# Redirect-bearing param names — open-redirect probes (a superset that includes redirect/next/return)
_REDIRECT_PARAM_RE = re.compile(
    r"^(url|redirect|redirect_uri|redirecturl|redir|next|return|returnurl|return_url|dest|"
    r"destination|continue|goto|target|out|link|forward|to|u)$", re.I)


def _extract_params(body: str):
    found = set(_INPUT_NAME_RE.findall(body or ""))
    found.update(_COMMON_PARAMS)
    return sorted(found)


def recon(base_url, fetch, login_path="/rest/user/login", oob=None):
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
        candidates.append(Candidate("reflected-xss", f"/ (param {param})", base + "/", inject_field=param))
        candidates.append(Candidate("command-injection", f"/ (param {param})", base + "/", inject_field=param))
        candidates.append(Candidate("path-traversal", f"/ (param {param})", base + "/", inject_field=param))
        if oob is not None:
            candidates.append(Candidate("blind-command-injection", f"/ (param {param})", base + "/",
                                        inject_field=param, oracle={"oob": oob}))
            if _URL_PARAM_RE.match(param):
                candidates.append(Candidate("ssrf", f"/ (param {param})", base + "/",
                                            inject_field=param, oracle={"oob": oob}))
            if _REDIRECT_PARAM_RE.match(param):
                candidates.append(Candidate("open-redirect", f"/ (param {param})", base + "/",
                                            inject_field=param, oracle={"oob": oob}))
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
    "excessive-data-exposure": "high",
    "mass-assignment": "high",
    "broken-authentication": "critical",
    "xss": "high",
    "stored-xss": "high",
    "xxe": "high",
    "nosql-injection": "critical",
    "command-injection": "critical",
    "open-redirect": "medium",
}


def _urllib_request():
    import json as _json
    import urllib.error
    import urllib.request

    def request(method, url, json=None, headers=None, data=None):
        h = dict(headers or {})
        body = None
        if json is not None:
            body = _json.dumps(json).encode()
            h.setdefault("Content-Type", "application/json")
        elif data is not None:                       # raw body (e.g. XML for XXE); caller sets CT
            body = data.encode() if isinstance(data, str) else data
        req = urllib.request.Request(url, data=body, method=method, headers=h)
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
    and victim. Returns (transport, victim_resource_id, attacker_resource_id, attacker_token) — the
    ids let the caller form the IDOR + negative-control candidates; the token feeds the weak-JWT
    verifier."""
    # Role callables default to GET (read-side verifiers call role(url)) but carry their auth into
    # writes too: role(url, method="POST", json=body) — needed by the write-side verifier.
    by_role = {"anon": lambda u, method="GET", json=None: request(method, u, json=json)}
    victim_id = attacker_id = ta = None
    creds = list(credentials or [])
    if len(creds) >= 2:
        from grin.login_discovery import discover_login, shape_login
        from grin.tools.idor_probe import login_session
        post = lambda u, b: request("POST", u, json=b)   # noqa: E731
        cid = lambda c: c.get("login") or c.get("email") or c.get("username")   # noqa: E731
        # Generalize recon: discover the login shape (path / cred field / token location) by an
        # identity-proven login, instead of assuming Juice Shop's. Fall back to the legacy login
        # only when nothing is proven, so a non-discoverable target behaves exactly as before.
        shape = discover_login(base_url, cid(creds[0]), creds[0]["password"], post)
        if shape is not None:
            ta, attacker_id = shape_login(base_url, cid(creds[0]), creds[0]["password"], post, shape)
            tb, victim_id = shape_login(base_url, cid(creds[1]), creds[1]["password"], post, shape)
        else:
            ta, attacker_id = login_session(base_url, cid(creds[0]), creds[0]["password"],
                                            post, login_path)
            tb, victim_id = login_session(base_url, cid(creds[1]), creds[1]["password"],
                                          post, login_path)
        if ta:
            by_role["attacker"] = lambda u, method="GET", json=None, t=ta: request(
                method, u, json=json, headers={"Authorization": "Bearer " + t})
        if tb:
            by_role["victim"] = lambda u, method="GET", json=None, t=tb: request(
                method, u, json=json, headers={"Authorization": "Bearer " + t})
    return Transport(request=request, by_role=by_role), victim_id, attacker_id, ta


def run_cookie_general(base_url, credentials, protected_url, *, start_path="/",
                       extra_cookies=None, request_full=None, target="", oob=None, allow_post=False,
                       allow_destructive=False):
    """Fully autonomous assessment of a cookie-session app (no OpenAPI): auto-discover + drive the
    login form, crawl the authenticated surface for injection points, and verify them. Returns the
    confirmed findings ([] if login could not be established). allow_post (operator opt-in) lets the
    crawler probe allowlisted compute/lookup POST forms (e.g. exec/ping); allow_destructive lets it
    write to persistent content sinks (stored-XSS) — both off by default. A CONFIRMED stored-XSS needs
    a distinct reader: 'anon' (built always) proves a public render; pass a 2nd credential for a
    cross-account 'victim' reader when the render page is login-gated."""
    from grin.cookie_auth import build_cookie_transport_auto
    from grin.crawl import crawl_injection_points
    transport, _n, _spec = build_cookie_transport_auto(
        base_url, credentials, protected_url, extra_cookies=extra_cookies, request_full=request_full)
    attacker = transport.by_role.get("attacker")
    if attacker is None:
        return []
    post_out = [] if (allow_post or allow_destructive) else None
    points, status = crawl_injection_points(base_url.rstrip("/") + start_path, lambda u: attacker(u),
                                            allow_post=allow_post, allow_destructive=allow_destructive,
                                            post_out=post_out)
    if status == "deauth":      # the crawl lost the session — never verify against a dead session
        return []
    candidates = []
    for pf in (post_out or []):                 # opt-in POST-form candidates (archetype-allowlisted)
        for cls in pf["classes"]:
            if cls == "stored-xss":             # content sink: write then read the render page back
                candidates.append(Candidate("stored-xss", pf["location"], pf["action"], method="POST",
                                            inject_field=pf["field"],
                                            oracle={"form": True, "form_url": pf["form_url"],
                                                    "view_url": pf["form_url"]}))
                continue
            candidates.append(Candidate(cls, pf["location"], pf["action"], method="POST",
                                        inject_field=pf["field"],
                                        oracle={"form": True, "form_url": pf["form_url"]}))
            if cls == "command-injection" and oob is not None:   # also the blind (no-output) path
                candidates.append(Candidate("blind-command-injection", pf["location"], pf["action"],
                                            method="POST", inject_field=pf["field"],
                                            oracle={"form": True, "form_url": pf["form_url"], "oob": oob}))
    for loc, url, field in points:
        candidates.append(Candidate("sqli-error", loc, url, inject_field=field))
        candidates.append(Candidate("reflected-xss", loc, url, inject_field=field))
        candidates.append(Candidate("command-injection", loc, url, inject_field=field))
        candidates.append(Candidate("path-traversal", loc, url, inject_field=field))
        if oob is not None:
            candidates.append(Candidate("blind-command-injection", loc, url, inject_field=field, oracle={"oob": oob}))
            if _URL_PARAM_RE.match(field):
                candidates.append(Candidate("ssrf", loc, url, inject_field=field, oracle={"oob": oob}))
            if _REDIRECT_PARAM_RE.match(field):
                candidates.append(Candidate("open-redirect", loc, url, inject_field=field, oracle={"oob": oob}))
    return assess(candidates, transport, target=target or base_url)


def _endpoint_exists(transport, url):
    """Cheap existence probe (GET): True unless the endpoint is absent (404) or unreachable.
    Guards destructive writes from firing blindly at a path that isn't there."""
    try:
        status, _b = transport.request("GET", url)
    except Exception:
        return False
    return bool(status) and status != 404


def run_general(base_url, credentials=None, *, request=None,
                resource_template="/rest/basket/{id}", login_path="/rest/user/login",
                review_template="/rest/products/{pid}/reviews", review_pid=1, target="",
                allow_destructive=False, oob=None):
    """End-to-end: build the transport (sessions), recon the surface, resolve the session-coupled
    IDOR + write-side-BAC candidates, and assess everything. Deterministic; the LLM is not in this
    path."""
    request = request or _urllib_request()
    base = base_url.rstrip("/")
    creds = list(credentials or [])
    cid = lambda c: c.get("login") or c.get("email") or c.get("username")   # noqa: E731
    transport, victim_id, attacker_id, attacker_token = build_transport(
        request, base_url, credentials, login_path)
    candidates = recon(base_url, transport.by_role["anon"], login_path=login_path, oob=oob)
    have_two = "attacker" in transport.by_role and "victim" in transport.by_role
    if victim_id is not None and attacker_id is not None and have_two:
        # Require BOTH ids so the negative control is always present — without the attacker's own
        # resource, the shared/default-template guard can't run and an empty template would FP.
        url = base + resource_template.replace("{id}", str(victim_id))
        own = base + resource_template.replace("{id}", str(attacker_id))
        candidates.append(Candidate("idor", resource_template, url, oracle={"attacker_own_url": own}))
    from grin.resource_discovery import (discover_idor_candidates, discover_sqli_candidates,
                                          discover_exposure_candidates, discover_mass_assignment_target,
                                          discover_protected_endpoint, discover_xxe_candidates,
                                          discover_login_candidates)
    # broken auth: is the JWT signing secret weak enough to forge tokens? (needs a real token)
    if attacker_token:
        vurl = discover_protected_endpoint(base_url, transport.by_role)
        if vurl:
            candidates.append(Candidate("jwt-weak-secret", "JWT signing secret", base_url,
                                        oracle={"token": attacker_token, "verify_url": vurl}))
    # mass assignment: self-registers control/treatment accounts (DESTRUCTIVE; only when the target
    # exposes a register + profile endpoint, so apps like Juice Shop are never touched by it)
    ma = discover_mass_assignment_target(base_url, transport.by_role) if allow_destructive else None
    if ma:
        candidates.append(Candidate("mass-assignment", ma["register_url"][len(base):] or "/register",
                                    ma["register_url"], oracle=ma))
    # error-based SQLi at OpenAPI detail-path params (needs no auth; the oracle is self-verifying)
    for loc, url_template in discover_sqli_candidates(base_url, transport.by_role):
        candidates.append(Candidate("sqli-error", loc, url_template,
                                    oracle={"inject": "path", "url_template": url_template}))
    # excessive data exposure at anon-readable data endpoints (side-effecting GETs are excluded)
    for loc, url in discover_exposure_candidates(base_url, transport.by_role):
        candidates.append(Candidate("excessive-data-exposure", loc, url))
    # XXE at endpoints whose OpenAPI requestBody accepts XML (benign probe; no recursive entities)
    for loc, url in discover_xxe_candidates(base_url, transport.by_role):
        candidates.append(Candidate("xxe", loc, url, method="POST", oracle={"oob": oob} if oob else {}))
    # NoSQL operator-injection auth bypass at OpenAPI login endpoints (differential, no-auth probe)
    for loc, url, uf, pf in discover_login_candidates(base_url, transport.by_role):
        candidates.append(Candidate("nosql-injection", loc, url, method="POST",
                                    oracle={"user_field": uf, "pass_field": pf}))
    if have_two:
        # Generalize beyond the login-derived id: discover victim-owned resources from the target's
        # OpenAPI surface (ownership-proven, conservative). The hardened oracle is the precision gate.
        for loc, vurl, aurl in discover_idor_candidates(
                base_url, transport.by_role, cid(creds[1]), cid(creds[0])):
            candidates.append(Candidate("idor", loc, vurl, oracle={"attacker_own_url": aurl}))
    if have_two and len(creds) >= 2 and allow_destructive and _endpoint_exists(transport, base
                                                                              + review_template.replace("{pid}", str(review_pid))):
        # write-side BAC: forge a review attributed to the victim's identity. The harness owns the
        # identities (the login ids); location is the report key, the oracle carries live URLs.
        # Gated by an existence probe so we never fire a blind PUT at a non-review target.
        review_url = base + review_template.replace("{pid}", str(review_pid))
        candidates.append(Candidate(
            "forged-review", "/rest/products/reviews", review_url,
            oracle={
                "write_url": review_url, "read_url": review_url, "write_method": "PUT",
                "body_template": {}, "forged_field": "author", "marker_field": "message",
                "forged_value": cid(creds[1]), "control_value": cid(creds[0]),
                "attacker_identity": [cid(creds[0])],
            }))
    return assess(candidates, transport, target=target or base_url)


def _dedup_bac_dirs(findings):
    """A bare directory (location ending '/') and the files under it are the SAME exposure; when
    a file under it also confirmed, drop the directory finding (matches bac-probe's behavior)."""
    bac = {f.location for f in findings if f.vuln_class == "broken-access-control"}
    out = []
    for f in findings:
        if (f.vuln_class == "broken-access-control" and f.location.endswith("/")
                and any(o != f.location and o.startswith(f.location) for o in bac)):
            continue
        out.append(f)
    return out


# OOB classes that defer to a single run-level poll window (each fires one token, one predicate).
# XXE is excluded on purpose: its GE->PE fallback needs distinct inline evidence per arm.
_OOB_DEFER_CLASSES = {"ssrf", "blind-command-injection", "open-redirect"}


def _finding(vuln_class, location, target, url, evidence):
    return Finding(
        title=f"{vuln_class}: {location}",
        target=target or url,
        severity=_SEVERITY.get(vuln_class, "medium"),
        evidence=evidence,
        tool="grin-verify",
        command=f"verify[{vuln_class}] {url}",
        recommendation="",
        vuln_class=vuln_class,
        location=location,
    )


def assess(candidates, transport, target: str = ""):
    """Verify every candidate; return a Finding for each CONFIRMED verdict. OOB callback classes
    (ssrf/blind-cmdi/open-redirect) FIRE their probes during the main pass and resolve in ONE
    run-level poll window at the end — turning N sequential per-candidate waits into a single wait."""
    from grin.verify import _oob_hits
    oob = next((c.oracle.get("oob") for c in candidates
                if isinstance(c.oracle, dict) and c.oracle.get("oob")), None)
    pending = [] if oob is not None else None
    findings = []
    for c in candidates:
        if pending is not None and isinstance(c.oracle, dict) and c.oracle.get("oob") \
                and c.vuln_class in _OOB_DEFER_CLASSES:
            c.oracle["oob_defer"] = pending          # opt the verifier into deferral
        verdict = verify(c, transport)
        if verdict.status != CONFIRMED:
            continue
        findings.append(_finding(verdict.vuln_class, verdict.location, target, c.url, verdict.evidence))

    if pending:                                       # single poll window resolves every deferred probe
        timeout = max((c.oracle.get("ssrf_timeout", 3) for c in candidates
                       if isinstance(c.oracle, dict)), default=3)
        unresolved, deadline = list(range(len(pending))), time.time() + float(timeout)
        done = {}
        while unresolved and time.time() < deadline:
            still = []
            for i in unresolved:
                ev = None
                for pr in pending[i]["probes"]:
                    hit = _oob_hits(oob, pr["tokens"], pr["pred"])
                    if hit:
                        ev = pr["evidence_fn"](hit)
                        break
                if ev is not None:
                    done[i] = ev
                else:
                    still.append(i)
            if not still:
                break
            unresolved = still
            time.sleep(0.25)
        for i in sorted(done):
            rec = pending[i]
            findings.append(_finding(rec["vuln_class"], rec["location"], target, target, done[i]))
    for c in candidates:        # don't leave per-run deferral state on a (possibly reused) oracle dict
        if isinstance(c.oracle, dict):
            c.oracle.pop("oob_defer", None)
    return _dedup_bac_dirs(findings)
