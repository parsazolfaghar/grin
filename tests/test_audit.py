import json
from grin.audit import audit, result_digest


def test_audit_appends_one_line_with_schema(tmp_path):
    path = str(tmp_path / "a.jsonl")
    rec = audit(path, engagement="e1", target="203.0.113.7", tool="nmap",
                command="nmap -sV 203.0.113.7", action_class="active-scan",
                decision="allow", gated=False, approved_by=None, exit_code=0,
                result_digest="sha256:abc", duration_s=4.1)
    lines = open(path).read().splitlines()
    assert len(lines) == 1
    loaded = json.loads(lines[0])
    assert loaded["engagement"] == "e1"
    assert loaded["decision"] == "allow"
    assert loaded["action_class"] == "active-scan"
    assert loaded["exit_code"] == 0
    assert "ts" in loaded
    assert rec["command"] == "nmap -sV 203.0.113.7"


def test_audit_is_append_only(tmp_path):
    path = str(tmp_path / "a.jsonl")
    audit(path, engagement="e1", target="t", tool="nmap", command="c1",
          action_class="passive", decision="allow", gated=False)
    audit(path, engagement="e1", target="t", tool="sqlmap", command="c2",
          action_class="exploit", decision="refuse", gated=False, reason="out of scope")
    lines = open(path).read().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["command"] == "c1"
    assert json.loads(lines[1])["decision"] == "refuse"
    assert json.loads(lines[1])["reason"] == "out of scope"


def test_refusal_carries_reason(tmp_path):
    path = str(tmp_path / "a.jsonl")
    audit(path, engagement="e1", target="t", tool="x", command="c",
          action_class="exploit", decision="refuse", gated=True, reason="operator denied",
          approved_by="operator")
    rec = json.loads(open(path).read().splitlines()[0])
    assert rec["reason"] == "operator denied"
    assert rec["approved_by"] == "operator"


def test_result_digest_format():
    d = result_digest("hello")
    assert d.startswith("sha256:")
    assert len(d) == len("sha256:") + 64
