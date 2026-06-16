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
    assert reloaded.env["kind"] == "auto"
    assert "exploit" in reloaded.roe.allowed_actions
    assert eng.id.startswith("adhoc-")
    with open(reloaded.audit_log) as fh:
        rec = json.loads(fh.readline())
    assert rec["event"] == "authorized"
    assert rec["prompt"] == "bypass login page for www.test.com"
    assert rec["operator"] == "operator"
    assert rec["scope"] == ["www.test.com"]


def test_build_bare_target_defaults_not_aggressive_env_auto(tmp_path):
    # the bare-target -> aggressive heuristic is retired; aggression now follows strength
    # (default "normal" => not aggressive). env still self-selects via auto.
    intent = parse_intent("www.test.com")
    eng, path = build_adhoc_engagement(
        intent, now=datetime(2026, 6, 15, 19, 30, 0), operator="op", root=str(tmp_path))
    assert eng.aggressive is False
    assert load_engagement(path).aggressive is False
    assert load_engagement(path).env["kind"] == "auto"


def test_build_carries_stealth(tmp_path):
    from datetime import datetime
    from grin.engagement import load_engagement
    from grin.intent import parse_intent
    from grin.adhoc import build_adhoc_engagement
    intent = parse_intent("www.test.com")
    _eng, path = build_adhoc_engagement(intent, now=datetime(2026, 6, 15, 12, 0, 0),
                                        operator="op", root=str(tmp_path), stealth="paranoid")
    assert load_engagement(path).stealth == "paranoid"


def test_build_recon_caps_actions_and_records_strength(tmp_path):
    from datetime import datetime
    from grin.engagement import load_engagement
    from grin.intent import parse_intent
    from grin.adhoc import build_adhoc_engagement
    intent = parse_intent("www.test.com")
    _eng, path = build_adhoc_engagement(intent, now=datetime(2026, 6, 15, 12, 0, 0),
                                        operator="op", root=str(tmp_path), strength="recon")
    e = load_engagement(path)
    assert e.strength == "recon"
    assert e.roe.allowed_actions == ["passive", "active-scan"]


def test_build_aggressive_keeps_actions(tmp_path):
    from datetime import datetime
    from grin.engagement import load_engagement
    from grin.intent import parse_intent
    from grin.adhoc import build_adhoc_engagement
    intent = parse_intent("www.test.com")
    _eng, path = build_adhoc_engagement(intent, now=datetime(2026, 6, 15, 12, 0, 0),
                                        operator="op", root=str(tmp_path), strength="aggressive")
    e = load_engagement(path)
    assert e.strength == "aggressive"
    assert "exploit" in e.roe.allowed_actions


def test_build_aggressive_flag_follows_strength(tmp_path):
    from datetime import datetime
    from grin.engagement import load_engagement
    from grin.intent import parse_intent
    from grin.adhoc import build_adhoc_engagement
    intent = parse_intent("www.test.com")               # bare target (old heuristic would force True)
    _e, p_norm = build_adhoc_engagement(intent, now=datetime(2026, 6, 15, 12, 0, 0),
                                        operator="op", root=str(tmp_path / "n"), strength="normal")
    assert load_engagement(p_norm).aggressive is False  # strength normal -> not aggressive on disk
    _e2, p_agg = build_adhoc_engagement(intent, now=datetime(2026, 6, 15, 12, 0, 0),
                                        operator="op", root=str(tmp_path / "a"), strength="max")
    assert load_engagement(p_agg).aggressive is True


def test_build_writes_tool_acquire_env(tmp_path):
    from datetime import datetime
    from grin.engagement import load_engagement
    from grin.intent import parse_intent
    from grin.adhoc import build_adhoc_engagement
    intent = parse_intent("www.test.com")
    _e, path = build_adhoc_engagement(intent, now=datetime(2026, 6, 15, 12, 0, 0),
                                      operator="op", root=str(tmp_path), tool_acquire="never")
    env = load_engagement(path).env
    assert env["kind"] == "auto"
    assert env["tool_acquire"] == "never"
    assert env["tool_requests"].endswith(".tools.json")
