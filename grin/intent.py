"""Parse an operator's free-text prompt into a target + goal. Primary path asks the active brain
for strict JSON; deterministic regex fallback when no client / client down / unparseable. Never
raises — worst case returns the raw text as the goal with no target."""
import re
from dataclasses import dataclass, field

from grin.jsonextract import extract_json

_URL = re.compile(r'https?://[^\s]+', re.I)
_CIDR = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b')
_IPV4 = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')
_HOST = re.compile(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b', re.I)
_FILLER = ("for", "on", "against", "the", "at", "to", "of")


def classify_target(token: str) -> str:
    t = (token or "").strip()
    if not t:
        return "unknown"
    if _URL.fullmatch(t) or t.lower().startswith("www."):
        return "web-url"
    if _CIDR.fullmatch(t):
        return "cidr-network"
    if _IPV4.fullmatch(t):
        return "ip-host"
    if _HOST.fullmatch(t):
        return "hostname"
    return "unknown"


@dataclass(frozen=True)
class Intent:
    raw: str
    goal: str
    targets: list = field(default_factory=list)
    target_type: str = "unknown"
    bare_target: bool = False


def _first_target(text: str):
    for rx in (_URL, _CIDR, _IPV4, _HOST):
        m = rx.search(text)
        if m:
            return m.group(0)
    return None


def _strip_goal(text: str, token: str) -> str:
    rest = text.replace(token, " ")
    words = [w for w in rest.split() if w.lower() not in _FILLER]
    return " ".join(words).strip()


def _regex_intent(text: str) -> Intent:
    token = _first_target(text)
    if not token:
        return Intent(raw=text, goal=text.strip(), targets=[], target_type="unknown",
                      bare_target=False)
    ttype = classify_target(token)
    goal = _strip_goal(text, token)
    bare = goal == ""
    if bare:
        goal = f"comprehensive assessment of {token}"
    return Intent(raw=text, goal=goal, targets=[token], target_type=ttype, bare_target=bare)


_SYSTEM = ("You extract a single penetration-test target and the operator's goal from their text. "
           "Return ONLY JSON: {\"targets\": [\"...\"], \"goal\": \"...\", "
           "\"target_type\": \"web-url|ip-host|cidr-network|hostname|unknown\"}. "
           "If there is no explicit task verb, return goal as an empty string.")


def parse_intent(text: str, client=None, model: str = "") -> Intent:
    text = (text or "").strip()
    if not text:
        return Intent(raw="", goal="", targets=[], target_type="unknown", bare_target=False)
    if client is not None:
        try:
            if client.is_up():
                raw = client.generate(model=model, system=_SYSTEM, prompt=text, temperature=0.0)
                data = extract_json(raw, want=("targets", "goal"))
                if data:
                    targets = [str(t) for t in (data.get("targets") or []) if str(t).strip()]
                    goal = str(data.get("goal") or "").strip()
                    ttype = str(data.get("target_type") or "").strip() or (
                        classify_target(targets[0]) if targets else "unknown")
                    bare = bool(targets) and goal == ""
                    if bare:
                        goal = f"comprehensive assessment of {targets[0]}"
                    return Intent(raw=text, goal=goal or text, targets=targets,
                                  target_type=ttype, bare_target=bare)
        except Exception:  # noqa: BLE001 - any LLM/parse failure falls back to regex
            pass
    return _regex_intent(text)
