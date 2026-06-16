import json
import os
from datetime import datetime

from grin.engagement import load_engagement
from grin.intent import parse_intent
from grin.adhoc import build_adhoc_engagement, normalize_target


def test_normalize_target_strips_scheme_and_path():
    assert normalize_target("https://www.test.com/login?x=1") == "www.test.com"
    assert normalize_target("www.test.com") == "www.test.com"
    assert normalize_target("10.0.0.0/24") == "10.0.0.0/24"


def test_build_writes_valid_engagement_and_authorization(tmp_path):
    intent = parse_intent("bypass login page for www.test.com")
    root = tmp_path / "eng"
    eng, path = build_adhoc_engagement(
        intent, now=datetime(2026, 6, 15, 19, 30, 0), operator="operator", root=str(root))
    reloaded = load_engagement(path)
    assert reloaded.mode == "adhoc"
    assert reloaded.scope.include == ["www.test.com"]
    assert reloaded.autonomy == "autonomous"
    assert reloaded.env == {"kind": "auto"}
    assert "exploit" in reloaded.roe.allowed_actions
    assert eng.id.startswith("adhoc-")
    with open(reloaded.audit_log) as fh:
        rec = json.loads(fh.readline())
    assert rec["event"] == "authorized"
    assert rec["prompt"] == "bypass login page for www.test.com"
    assert rec["operator"] == "operator"
    assert rec["scope"] == ["www.test.com"]


def test_build_bare_target_sets_aggressive(tmp_path):
    intent = parse_intent("www.test.com")
    eng, path = build_adhoc_engagement(
        intent, now=datetime(2026, 6, 15, 19, 30, 0), operator="op", root=str(tmp_path))
    assert eng.aggressive is True
    assert load_engagement(path).aggressive is True
    assert load_engagement(path).env == {"kind": "auto"}


def test_build_carries_stealth(tmp_path):
    from datetime import datetime
    from grin.engagement import load_engagement
    from grin.intent import parse_intent
    from grin.adhoc import build_adhoc_engagement
    intent = parse_intent("www.test.com")
    _eng, path = build_adhoc_engagement(intent, now=datetime(2026, 6, 15, 12, 0, 0),
                                        operator="op", root=str(tmp_path), stealth="paranoid")
    assert load_engagement(path).stealth == "paranoid"
