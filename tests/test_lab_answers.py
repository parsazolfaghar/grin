import pytest
from grin.lab.answers import load_answers, AnswerKeyError, Target


def _yaml(tmp_path, body):
    p = tmp_path / "answers.yaml"
    p.write_text(body)
    return str(p)


def test_load_valid_answers(tmp_path):
    path = _yaml(tmp_path, """
targets:
  - id: t1-ssh
    container: grin-lab-ssh
    ip: 172.30.0.11
    tier: easy
    open_ports: [22]
    vuln_class: weak-credentials
    expected_findings: ["ssh weak credentials"]
    flag: "GRIN{abc}"
    win: flag-in-loot
""")
    targets = load_answers(path)
    assert len(targets) == 1
    t = targets[0]
    assert isinstance(t, Target)
    assert t.id == "t1-ssh" and t.ip == "172.30.0.11"
    assert t.open_ports == [22] and t.flag == "GRIN{abc}"
    assert t.expected_findings == ["ssh weak credentials"]
    assert t.extra_scope == []   # optional field defaults empty when absent


def test_extra_scope_loads_when_present(tmp_path):
    path = _yaml(tmp_path, """
targets:
  - {id: t6-pivot, container: d, ip: 172.30.0.16, tier: master, open_ports: [80],
     vuln_class: lateral-movement, expected_findings: ["y"], flag: "GRIN{b}", win: flag-in-loot,
     extra_scope: ["172.30.0.17"]}
""")
    assert load_answers(path)[0].extra_scope == ["172.30.0.17"]


def test_missing_required_field_raises(tmp_path):
    path = _yaml(tmp_path, """
targets:
  - id: t1-ssh
    ip: 172.30.0.11
""")
    with pytest.raises(AnswerKeyError):
        load_answers(path)


def test_empty_or_no_targets_raises(tmp_path):
    path = _yaml(tmp_path, "targets: []\n")
    with pytest.raises(AnswerKeyError):
        load_answers(path)


def test_by_id_lookup(tmp_path):
    path = _yaml(tmp_path, """
targets:
  - {id: t1-ssh, container: c, ip: 172.30.0.11, tier: easy, open_ports: [22],
     vuln_class: weak-credentials, expected_findings: ["x"], flag: "GRIN{a}", win: flag-in-loot}
  - {id: t2-web, container: d, ip: 172.30.0.12, tier: medium, open_ports: [80],
     vuln_class: command-injection, expected_findings: ["y"], flag: "GRIN{b}", win: flag-in-loot}
""")
    targets = load_answers(path)
    from grin.lab.answers import by_id
    assert by_id(targets, "t2-web").ip == "172.30.0.12"
    assert by_id(targets, "nope") is None
