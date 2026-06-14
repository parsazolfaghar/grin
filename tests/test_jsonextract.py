from grin.jsonextract import extract_json


def test_first_valid_object():
    assert extract_json('{"a": 1} {"b": 2}') == {"a": 1}


def test_want_selects_object_with_key():
    raw = '{"junk": 1} prose {"action": {"tool": "nmap"}}'
    assert extract_json(raw, want=("action",))["action"]["tool"] == "nmap"


def test_two_blocks_action_then_done_returns_action():
    # the WhiteRabbitNeo failure mode: a valid action, then prose, then an echoed done-template
    raw = ('To exploit:\n```json\n{"action": {"tool": "sqlmap", "command": "sqlmap -u x"}}\n```\n'
           'This will... If done, reply:\n```json\n{"done": true, "findings": []}\n```')
    obj = extract_json(raw, want=("action", "done", "findings"))
    assert "action" in obj and obj["action"]["tool"] == "sqlmap"


def test_braces_inside_strings_dont_break_balance():
    raw = '{"why": "use {curly} braces", "tool": "nmap"}'
    assert extract_json(raw) == {"why": "use {curly} braces", "tool": "nmap"}


def test_malformed_candidate_skipped_returns_next_valid():
    raw = '{not valid json} {"action": {"tool": "nmap"}}'
    assert extract_json(raw, want=("action",))["action"]["tool"] == "nmap"


def test_no_json_returns_none():
    assert extract_json("just prose, no objects here") is None


def test_want_unmatched_returns_none():
    assert extract_json('{"x": 1} {"y": 2}', want=("action",)) is None


def test_nested_object_returns_outer():
    assert extract_json('{"a": {"b": 1}}') == {"a": {"b": 1}}
