from grin.intent import classify_target, parse_intent


def test_classify_target_table():
    assert classify_target("https://test.com/login") == "web-url"
    assert classify_target("www.test.com") == "web-url"
    assert classify_target("10.0.0.5") == "ip-host"
    assert classify_target("10.0.0.0/24") == "cidr-network"
    assert classify_target("test.com") == "hostname"
    assert classify_target("not a target") == "unknown"


def test_parse_task_with_target():
    i = parse_intent("bypass login page for www.test.com")
    assert i.targets == ["www.test.com"]
    assert i.target_type == "web-url"
    assert "bypass login page" in i.goal.lower()
    assert i.bare_target is False


def test_parse_bare_target():
    i = parse_intent("www.test.com")
    assert i.targets == ["www.test.com"]
    assert i.bare_target is True
    assert "www.test.com" in i.goal


def test_parse_no_target():
    i = parse_intent("do something vague")
    assert i.targets == []
    assert i.target_type == "unknown"
    assert i.bare_target is False


def test_parse_uses_llm_when_client_given():
    class FakeClient:
        def is_up(self): return True
        def generate(self, **k):
            return '{"targets": ["10.0.0.9"], "goal": "find creds", "target_type": "ip-host"}'
    i = parse_intent("anything", client=FakeClient(), model="m")
    assert i.targets == ["10.0.0.9"]
    assert i.goal == "find creds"
    assert i.target_type == "ip-host"


def test_parse_falls_back_when_client_down():
    class DownClient:
        def is_up(self): return False
        def generate(self, **k): raise AssertionError("must not call")
    i = parse_intent("scan 10.0.0.5", client=DownClient(), model="m")
    assert i.targets == ["10.0.0.5"]
    assert i.target_type == "ip-host"


def test_parse_llm_caps_to_single_target():
    class MultiClient:
        def is_up(self): return True
        def generate(self, **k):
            return '{"targets": ["a.test.com", "b.test.com"], "goal": "x", "target_type": "web-url"}'
    i = parse_intent("anything", client=MultiClient(), model="m")
    assert i.targets == ["a.test.com"]   # extra targets dropped (scope locks to one)
