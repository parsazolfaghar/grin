#!/usr/bin/env python3
"""Deterministic web-app vulnerability scanner (`web-scan`).

grin's CLI toolset reaches ports, services, SSH and a web RCE once a foothold is known — but it had
no systematic way to FIND a reflected-XSS / injectable parameter in the first place. CLI scanners
either miss it or drown the agent in noise. This closes that gap the way `web-rce` closed payload
encoding: one deterministic pass that discovers the injection points, sprays each, and reports the
exact parameter + payload that came back UNescaped (a real, reproducible reflection — not a guess).

  web-scan --url http://t/
  web-scan --url http://t/search --param q
  web-scan --url http://t/login --method POST

What it does, deterministically:
  1. Fetch the page; pull existing query params + every <form> input name.
  2. Build the injection-point set = those names UNION a candidate list (so it tests params that are
     linked NOWHERE — the ones reading the HTML for links would never reveal).
  3. Spray each point with marker-tagged XSS payloads spanning the common contexts (raw HTML,
     attribute breakout, script-string breakout) and classify the reflection:
        raw      -> the payload came back verbatim  => INJECTABLE (reported as a finding)
        encoded  -> reflected but escaped by the app => not directly injectable
        none     -> no reflection
  4. Print each injectable hit as `XSS <context> param=<p> payload=<...>` so the agent has the exact
     reproducible evidence to record as a finding.

The detection logic (payloads / reflection classify / form + param extraction / injection-point
union) is pure and unit-tested. The HTTP loop is thin I/O. Self-contained (stdlib only) so it runs
on the Kali runner without grin installed — deployed as /usr/local/bin/web-scan, invoked by the
agent as an ordinary command and therefore still authorized + gated + audited by the spine."""
import argparse
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser

# Param names that commonly carry user input but are frequently UNLINKED in the page, so reading the
# HTML for links/comments never reveals them. Probing this set is the whole point.
CANDIDATE_PARAMS = [
    "q", "s", "search", "query", "name", "id", "page", "file", "path", "url",
    "redirect", "next", "lang", "view", "cat", "user", "keyword", "term", "msg", "ref",
]


def xss_payloads(marker: str) -> list[str]:
    """Marker-tagged payloads spanning the contexts a value can land in. The marker makes reflection
    unambiguous and lets us tell raw (injectable) from escaped."""
    return [
        marker,                                       # baseline: does input reflect at all?
        f"<svg/onload=alert('{marker}')>",            # raw HTML element
        f"\"><script>alert('{marker}')</script>",     # attribute breakout -> new tag
        f"<img src=x onerror=alert('{marker}')>",     # raw HTML, event handler
        f"';alert('{marker}');//",                    # inline-script string breakout
    ]


def classify(body: str, payload: str, marker: str) -> str | None:
    """How a payload came back — the core XSS signal. Pure.
      "raw"     -> payload reflected verbatim (special chars intact) => injectable.
      "encoded" -> marker present but payload's chars were escaped/stripped => app escaped it.
      None      -> no reflection."""
    if not payload or not body:
        return None
    if payload in body:
        return "raw"
    if marker and marker in body:
        return "encoded"
    return None


def query_params(url: str) -> list[str]:
    """Existing query-string parameter names in `url` (order-preserving). Pure."""
    q = urllib.parse.urlsplit(url).query
    seen, out = set(), []
    for k, _ in urllib.parse.parse_qsl(q, keep_blank_values=True):
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


@dataclass
class Form:
    action: str
    method: str
    inputs: list[dict] = field(default_factory=list)  # [{"name":..., "type":...}]


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: list[Form] = []
        self._cur: Form | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = Form(action=a.get("action", ""),
                             method=(a.get("method", "get") or "get").lower())
            self.forms.append(self._cur)
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            self._cur.inputs.append({"name": a.get("name", ""), "type": a.get("type", tag)})

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None


def extract_forms(html: str) -> list[Form]:
    """Parse <form>s and their named inputs. Pure (stdlib parser)."""
    p = _FormParser()
    try:
        p.feed(html or "")
    except Exception:
        pass
    return p.forms


def injection_points(url: str, html: str) -> list[str]:
    """The de-duplicated set of parameter names worth spraying: existing URL params + form input
    names + the candidate list. Order: discovered-first (more likely live), then candidates. Pure."""
    out, seen = [], set()
    def add(n):
        n = (n or "").strip()
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    for n in query_params(url):
        add(n)
    for f in extract_forms(html):
        for i in f.inputs:
            add(i["name"])
    for n in CANDIDATE_PARAMS:
        add(n)
    return out


# ---------------------------------------------------------------------------
# Runner (I/O)
# ---------------------------------------------------------------------------

def _fetch(url: str, timeout: float = 15.0) -> str:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except Exception as e:
        return f"[web-scan fetch error: {e}]"


def _send(url: str, param: str, value: str, method: str, timeout: float = 15.0) -> str:
    data = urllib.parse.urlencode({param: value}).encode()
    try:
        if method.upper() == "POST":
            req = urllib.request.Request(
                url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
        else:
            sep = "&" if "?" in url else "?"
            req = urllib.request.Request(url + sep + urllib.parse.urlencode({param: value}))
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except Exception as e:
        return f"[web-scan request error: {e}]"


def scan(url: str, *, only_param: str | None = None, method: str = "GET") -> list[str]:
    """Spray each injection point with each XSS payload; return reproducible hit lines for every
    parameter that reflects a payload RAW (injectable). Reads the page to discover points first."""
    base = url.split("?", 1)[0]
    page = _fetch(url)
    points = [only_param] if only_param else injection_points(url, page)
    marker = "GRINxss"
    hits: list[str] = []
    contexts = {
        f"<svg/onload=alert('{marker}')>": "html-element",
        f"\"><script>alert('{marker}')</script>": "attr-breakout",
        f"<img src=x onerror=alert('{marker}')>": "event-handler",
        f"';alert('{marker}');//": "script-string",
    }
    for p in points:
        for payload in xss_payloads(marker):
            body = _send(base, p, payload, method)
            if classify(body, payload, marker) == "raw" and payload != marker:
                ctx = contexts.get(payload, "reflected")
                hits.append(f"XSS {ctx} param={p} payload={payload}")
                break  # one confirmed context per param is enough evidence; move on
    return hits


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="web-scan", description="Deterministic reflected-XSS scanner")
    ap.add_argument("--url", required=True)
    ap.add_argument("--param", default=None, help="test only this parameter (default: discover)")
    ap.add_argument("--method", choices=["GET", "POST"], default="GET")
    a = ap.parse_args(argv)
    hits = scan(a.url, only_param=a.param, method=a.method)
    if hits:
        print("\n".join(hits))
    else:
        print("[web-scan: no reflected-XSS injection point found]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
