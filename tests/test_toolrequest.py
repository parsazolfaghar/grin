from grin.toolrequest import ToolRequestStore, tool_requests_path


def test_request_dedupe_and_list(tmp_path):
    s = ToolRequestStore(str(tmp_path / "t.json"))
    s.request("sqlmap")
    s.request("sqlmap")
    s.request("nikto")
    assert sorted(s.requested()) == ["nikto", "sqlmap"]


def test_resolve_removes_from_requested(tmp_path):
    s = ToolRequestStore(str(tmp_path / "t.json"))
    s.request("sqlmap")
    s.resolve("sqlmap")
    assert s.requested() == []
    assert s.is_resolved("sqlmap") is True
    s.request("sqlmap")
    assert s.requested() == []


def test_deny_removes_from_requested(tmp_path):
    s = ToolRequestStore(str(tmp_path / "t.json"))
    s.request("hydra")
    s.deny("hydra")
    assert s.requested() == []
    assert s.is_denied("hydra") is True
    s.request("hydra")
    assert s.requested() == []


def test_missing_file_is_empty(tmp_path):
    assert ToolRequestStore(str(tmp_path / "nope.json")).requested() == []


def test_path_helper():
    class E:
        audit_log = "/x/audit/eng-1.jsonl"
    p = tool_requests_path(E())
    assert p.endswith(".tools.json") and "eng-1" in p
