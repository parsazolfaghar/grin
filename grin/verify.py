"""Composable verifiers — the heart of the general engine.

Design seam (validated with an independent review): uniform OUTPUT (`Verdict`), structured INPUTS
(`Candidate` describes WHAT to test; `Transport` is the harness-owned way to send requests, incl.
per-role sessions). A verifier runs ONLY its class-specific oracle — it NEVER logs in, mints
sessions, or discovers resource ids (the harness does that and hands it a ready `Candidate` +
`Transport`). One verifier per vuln CLASS, not per app.

A Verdict is CONFIRMED (oracle fired), REJECTED (clean negative), or INCONCLUSIVE (couldn't tell —
request failed, WAF/error status, or no oracle). Findings are emitted ONLY on CONFIRMED — code
decides whether a vuln is real, never the LLM. INCONCLUSIVE is a coverage gap, never a finding."""
from __future__ import annotations
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Mapping

CONFIRMED = "confirmed"
REJECTED = "rejected"
INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class Verdict:
    status: str          # confirmed | rejected | inconclusive
    vuln_class: str
    location: str
    evidence: str


@dataclass(frozen=True)
class Candidate:
    """What to test. The harness resolves auth/resource ids upstream into `url` + `oracle`."""
    vuln_class: str
    location: str                       # stable report key, e.g. "/search (param q)"
    url: str
    method: str = "GET"
    inject_field: str | None = None     # SSTI/SQLi: the param or JSON field to inject
    oracle: dict = field(default_factory=dict)   # class-specific params


@dataclass(frozen=True)
class Transport:
    """Harness-owned request surface. Verifiers never log in; they call these."""
    request: Callable[..., tuple]                       # (method, url, *, json=None, headers=None) -> (status, body)
    by_role: Mapping[str, Callable] = field(default_factory=dict)   # "anon"|"attacker"|"victim" -> fetch(url)


# --- SSTI -------------------------------------------------------------------------------------
# A distinctive arithmetic payload whose product is unlikely to appear by coincidence; a baseline
# request (a benign control value) guards against a page that already contains the product, so a
# coincidental match is not a false positive. Recall ceiling: this covers the {{...}} (jinja-style)
# engine family only — other engines (${...}, <%= %>, #{...}) need their own payloads.
_SSTI_PAYLOAD = "{{1234*5678}}"
_SSTI_PRODUCT = "7006652"
_SSTI_CONTROL = "grin-ssti-control"


def _with_param(url: str, field_name: str, value: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{field_name}={urllib.parse.quote(value)}"


def verify_ssti(candidate: Candidate, transport: Transport) -> Verdict:
    field_name = candidate.inject_field or "q"
    loc = candidate.location

    def send(value):
        if candidate.method.upper() == "POST":
            return transport.request("POST", candidate.url, json={field_name: value})
        return transport.request("GET", _with_param(candidate.url, field_name, value))

    try:
        _bstatus, bbody = send(_SSTI_CONTROL)
        pstatus, pbody = send(_SSTI_PAYLOAD)
    except Exception:
        return Verdict(INCONCLUSIVE, "ssti", loc, "request raised an exception")

    bbody, pbody = bbody or "", pbody or ""
    # Evaluated only when the product appears with the payload but NOT in the benign baseline.
    if _SSTI_PRODUCT in pbody and _SSTI_PRODUCT not in bbody:
        return Verdict(CONFIRMED, "ssti", loc,
                       f"{_SSTI_PAYLOAD} evaluated to {_SSTI_PRODUCT} (absent from the baseline)")
    if not pstatus or pstatus >= 400:
        return Verdict(INCONCLUSIVE, "ssti", loc, f"could not test cleanly (status {pstatus})")
    return Verdict(REJECTED, "ssti", loc, "payload not evaluated by a jinja-style template engine")


_REGISTRY: dict = {
    "ssti": verify_ssti,
}


def verify(candidate: Candidate, transport: Transport) -> Verdict:
    """Dispatch a candidate to its class verifier. Unknown class -> INCONCLUSIVE (no oracle)."""
    fn = _REGISTRY.get(candidate.vuln_class)
    if fn is None:
        return Verdict(INCONCLUSIVE, candidate.vuln_class, candidate.location,
                       f"no verifier for class {candidate.vuln_class!r}")
    return fn(candidate, transport)
