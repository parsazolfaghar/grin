from grin.results import ResultStore, results_path
from grin.engagement import validate_engagement

ENG = {
    "id": "e1", "name": "n", "mode": "client",
    "scope": {"in": ["*.acme.test"]},
    "roe": {"allowed_actions": ["passive"]},
    "autonomy": "action-gated", "env": {"kind": "local"},
    "audit_log": "./audit/e1.jsonl", "state": "active",
}


def test_results_path_derives_from_audit_log():
    eng = validate_engagement(ENG)
    assert results_path(eng) == "./audit/e1.results.jsonl"


def test_put_then_get(tmp_path):
    path = str(tmp_path / "e1.results.jsonl")
    s = ResultStore(path)
    s.put(id="abc123", command="nmap -sV x", output="80/open", exit_code=0)
    got = ResultStore(path).get("abc123")    # reload from disk
    assert got["command"] == "nmap -sV x"
    assert got["output"] == "80/open"
    assert got["exit_code"] == 0
    assert "ts" in got


def test_get_missing_returns_none(tmp_path):
    s = ResultStore(str(tmp_path / "none.results.jsonl"))
    assert s.get("nope") is None


def test_get_returns_latest_for_id(tmp_path):
    path = str(tmp_path / "e.results.jsonl")
    s = ResultStore(path)
    s.put(id="x", command="c1", output="first", exit_code=0)
    s.put(id="x", command="c2", output="second", exit_code=1)
    assert s.get("x")["output"] == "second"   # latest wins
