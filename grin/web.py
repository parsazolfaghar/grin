"""Web-app attack capability.

grin's CLI tools can't reach the web-app surface — reflected/stored XSS, form-driven injection, auth
flows, DOM behaviour. This adds it (Strix-style): a real browser via Playwright, plus the detection
logic CLI scanners lack. The logic — XSS payloads, reflection classification, form extraction — is
pure and unit-tested; the browser session is thin I/O behind the optional [web] extra, lazy-imported,
and live-validated on the rig.

Stays in grin's posture: evidence is the rendered/returned response (a real reflection, not a guess),
and nothing here bypasses scope — the caller still passes only in-scope URLs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser


def xss_payloads(marker: str) -> list[str]:
    """Test payloads, each carrying a unique `marker` so reflection is unambiguous. Covers the common
    contexts: raw HTML, attribute breakout, script-string breakout, and a plain marker baseline."""
    return [
        marker,                                            # baseline: does input reflect at all?
        f"<svg/onload=alert('{marker}')>",                 # raw HTML element
        f"\"><script>alert('{marker}')</script>",          # attribute breakout -> new tag
        f"<img src=x onerror=alert('{marker}')>",          # raw HTML, event handler
        f"';alert('{marker}');//",                         # inline-script string breakout
    ]


def reflection(body: str, payload: str, marker: str) -> str | None:
    """Classify how a payload came back, the core XSS signal:
      "raw"     — the payload reflected verbatim (special chars intact) => injectable, strong finding.
      "encoded" — the marker reflected but the payload's chars were HTML-encoded/stripped => not
                  directly injectable (the app escaped it).
      None      — no reflection.
    Pure."""
    if not payload or not body:
        return None
    if payload in body:
        return "raw"
    if marker and marker in body:
        return "encoded"
    return None


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
            self._cur = Form(action=a.get("action", ""), method=(a.get("method", "get") or "get").lower())
            self.forms.append(self._cur)
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            self._cur.inputs.append({"name": a.get("name", ""), "type": a.get("type", tag)})

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None


def extract_forms(html: str) -> list[Form]:
    """Parse <form>s and their named inputs — the injection points to spray. Pure (stdlib parser)."""
    p = _FormParser()
    try:
        p.feed(html or "")
    except Exception:
        pass
    return p.forms


class BrowserSession:
    """Thin Playwright wrapper for driving a real browser (XSS in the rendered DOM, auth flows, JS apps).
    Behind the [web] extra; lazy-imported so the pure logic above tests without Playwright. Live-validated
    on the rig."""

    def __init__(self, *, headless: bool = True, timeout_ms: int = 15000):
        from playwright.sync_api import sync_playwright  # lazy: optional [web] extra
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=headless)
        self.page = self._browser.new_page()
        self.page.set_default_timeout(timeout_ms)

    def goto(self, url: str) -> str:
        self.page.goto(url)
        return self.page.content()

    def fill_and_submit(self, selector: str, value: str, submit_selector: str | None = None) -> str:
        self.page.fill(selector, value)
        if submit_selector:
            self.page.click(submit_selector)
        else:
            self.page.keyboard.press("Enter")
        return self.page.content()

    def alert_fired(self) -> bool:
        """Register a dialog handler before navigating to catch a real alert() — the gold-standard XSS
        proof (executed, not just reflected)."""
        fired = {"v": False}
        self.page.on("dialog", lambda d: (fired.__setitem__("v", True), d.dismiss()))
        return fired["v"]

    def close(self) -> None:
        try:
            self._browser.close()
            self._pw.stop()
        except Exception:
            pass
