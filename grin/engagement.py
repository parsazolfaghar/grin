"""The engagement model — a pentest scope document, machine-enforced. Fail-closed:
any missing/invalid field raises EngagementError (callers treat that as 'refuse')."""
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import yaml

from grin.classes import ACTION_CLASSES

MODES = ("own-lab", "client", "adhoc")
AUTONOMY = ("autonomous", "action-gated", "phase-gated")
STATES = ("active", "paused", "done")
STEALTH_LEVELS = ("off", "quiet", "paranoid")


class EngagementError(Exception):
    """Raised on any invalid/missing engagement input. Fail-closed signal."""


@dataclass(frozen=True)
class Window:
    start: datetime
    end: datetime


@dataclass(frozen=True)
class Scope:
    include: list = field(default_factory=list)
    exclude: list = field(default_factory=list)


@dataclass(frozen=True)
class ROE:
    allowed_actions: list = field(default_factory=list)
    windows: list = field(default_factory=list)   # list[Window]


@dataclass(frozen=True)
class Engagement:
    id: str
    name: str
    mode: str
    scope: Scope
    roe: ROE
    autonomy: str
    env: dict
    audit_log: str
    state: str
    aggressive: bool = False
    stealth: str = "off"


def _require(data: dict, key: str):
    if key not in data or data[key] in (None, ""):
        raise EngagementError(f"missing required field: {key}")
    return data[key]


def _parse_dt(value: str) -> datetime:
    try:
        return datetime.fromisoformat(str(value))
    except (ValueError, TypeError) as e:
        raise EngagementError(f"unparseable datetime: {value!r}") from e


def validate_engagement(data: dict) -> Engagement:
    if not isinstance(data, dict):
        raise EngagementError("engagement must be a mapping")

    eid = str(_require(data, "id"))
    name = str(_require(data, "name"))

    mode = str(_require(data, "mode"))
    if mode not in MODES:
        raise EngagementError(f"invalid mode {mode!r}; expected one of {MODES}")

    autonomy = str(_require(data, "autonomy"))
    if autonomy not in AUTONOMY:
        raise EngagementError(f"invalid autonomy {autonomy!r}; expected one of {AUTONOMY}")

    state = str(_require(data, "state"))
    if state not in STATES:
        raise EngagementError(f"invalid state {state!r}; expected one of {STATES}")

    scope_raw = _require(data, "scope")
    if not isinstance(scope_raw, dict):
        raise EngagementError("scope must be a mapping")
    scope = Scope(include=list(scope_raw.get("in", []) or []),
                  exclude=list(scope_raw.get("exclude", []) or []))

    roe_raw = _require(data, "roe")
    if not isinstance(roe_raw, dict):
        raise EngagementError("roe must be a mapping")
    allowed = list(roe_raw.get("allowed_actions", []) or [])
    for c in allowed:
        if c not in ACTION_CLASSES:
            raise EngagementError(f"unknown ROE action class {c!r}; expected {ACTION_CLASSES}")
    windows = []
    for w in roe_raw.get("windows", []) or []:
        if not isinstance(w, dict) or "start" not in w or "end" not in w:
            raise EngagementError(f"window must have start+end: {w!r}")
        windows.append(Window(start=_parse_dt(w["start"]), end=_parse_dt(w["end"])))
    roe = ROE(allowed_actions=allowed, windows=windows)

    env = _require(data, "env")
    if not isinstance(env, dict) or "kind" not in env:
        raise EngagementError("env must be a mapping with a 'kind'")

    audit_log = str(_require(data, "audit_log"))

    stealth = str(data.get("stealth", "off") or "off")
    if stealth not in STEALTH_LEVELS:
        raise EngagementError(f"invalid stealth {stealth!r}; expected one of {STEALTH_LEVELS}")

    return Engagement(id=eid, name=name, mode=mode, scope=scope, roe=roe,
                      autonomy=autonomy, env=dict(env), audit_log=audit_log, state=state,
                      aggressive=bool(data.get("aggressive", False)),
                      stealth=stealth)


def load_engagement(path: str) -> Engagement:
    p = Path(path)
    if not p.exists():
        raise EngagementError(f"engagement file not found: {path}")
    try:
        data = yaml.safe_load(p.read_text())
    except yaml.YAMLError as e:
        raise EngagementError(f"invalid YAML: {e}") from e
    return validate_engagement(data)


def pending_path(engagement: Engagement) -> str:
    """The per-engagement state file (pending queue + approved phases) lives next to
    the audit log: <audit_dir>/<audit_stem>.state.json."""
    base, _ext = os.path.splitext(engagement.audit_log)
    return base + ".state.json"
