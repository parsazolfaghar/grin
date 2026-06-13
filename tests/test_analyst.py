import json
from ronin.analyst import initial_plan, replan, AnalystDecision
from ronin.objective import Objective
from ronin.inference import FakeClient
from ronin.finding import Finding


def test_initial_plan_parses_objectives():
    reply = json.dumps({"objectives": [
        {"objective": "enumerate hosts", "target": "203.0.113.0/24"},
        {"objective": "scan web", "target": "203.0.113.7"},
    ]})
    plan = initial_plan(FakeClient(reply), "m", "assess network", ["203.0.113.0/24"], [])
    assert plan == [Objective("enumerate hosts", "203.0.113.0/24"),
                    Objective("scan web", "203.0.113.7")]


def test_initial_plan_uses_seeds_in_prompt_and_still_parses():
    reply = json.dumps({"objectives": [{"objective": "scan", "target": "10.0.0.5"}]})
    plan = initial_plan(FakeClient(reply), "m", "assess", ["10.0.0.0/24"], ["10.0.0.5"])
    assert plan == [Objective("scan", "10.0.0.5")]


def test_initial_plan_parse_miss_returns_empty():
    assert initial_plan(FakeClient("no json here"), "m", "g", ["x"], []) == []


def test_initial_plan_skips_items_missing_fields():
    reply = json.dumps({"objectives": [
        {"objective": "ok", "target": "h"},
        {"objective": "", "target": "h"},
        {"objective": "no target"},
    ]})
    plan = initial_plan(FakeClient(reply), "m", "g", ["h"], [])
    assert plan == [Objective("ok", "h")]


def test_replan_parses_followups_and_done_false():
    reply = json.dumps({"done": False, "reason": "found a login page",
                        "next_objectives": [{"objective": "brute login", "target": "203.0.113.7"}]})
    d = replan(FakeClient(reply), "m", "goal", [], 1, 0)
    assert isinstance(d, AnalystDecision)
    assert d.done is False
    assert d.reason == "found a login page"
    assert d.next_objectives == [Objective("brute login", "203.0.113.7")]


def test_replan_done_true():
    reply = json.dumps({"done": True, "reason": "goal met", "next_objectives": []})
    d = replan(FakeClient(reply), "m", "goal", [Finding("t", "h", "low", "e", "nmap", "c")], 3, 0)
    assert d.done is True
    assert d.next_objectives == []


def test_replan_parse_miss_is_fail_soft():
    d = replan(FakeClient("garbage"), "m", "goal", [], 1, 0)
    assert d.done is False
    assert d.next_objectives == []
    assert "unparseable" in d.reason
