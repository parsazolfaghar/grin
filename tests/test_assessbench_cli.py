import json
from grin.cli import cmd_assessbench


def _findings_file(tmp_path, findings):
    p = tmp_path / "f.json"
    p.write_text(json.dumps(findings))
    return str(p)


def _f(title, vuln_class, location, severity="high"):
    return {"title": title, "target": "http://h:3000", "severity": severity,
            "evidence": "", "tool": "t", "command": "c",
            "vuln_class": vuln_class, "location": location}


def test_assessbench_scores_synthetic_findings(tmp_path, capsys):
    # two of juice-shop's three ground-truth bugs, correctly located -> precision 1.0
    findings = [
        _f("basket idor", "idor", "/rest/basket/5"),
        _f("forged review", "broken-access-control", "/rest/products/reviews"),
    ]
    rc = cmd_assessbench(target_id="juice-shop", findings=_findings_file(tmp_path, findings))
    out = capsys.readouterr().out
    assert rc == 0
    assert "precision" in out.lower()
    assert "1.00" in out          # no false positives


def test_assessbench_false_positive_lowers_precision(tmp_path, capsys):
    findings = [
        _f("basket idor", "idor", "/rest/basket/5"),
        _f("bogus", "sql-injection", "/nonexistent"),   # not in ground truth
    ]
    rc = cmd_assessbench(target_id="juice-shop", findings=_findings_file(tmp_path, findings))
    out = capsys.readouterr().out
    assert rc == 0
    assert "0.50" in out          # 1 tp / 2 reported
    assert "bogus" in out         # spurious listed


def test_assessbench_json_output(tmp_path, capsys):
    findings = [_f("x", "idor", "/rest/basket/5")]
    rc = cmd_assessbench(target_id="juice-shop",
                         findings=_findings_file(tmp_path, findings), json_out=True)
    j = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert j["target_id"] == "juice-shop" and j["tp"] == 1


def test_assessbench_ignores_extra_finding_keys(tmp_path, capsys):
    f = _f("x", "idor", "/rest/basket/5")
    f["unexpected_key"] = "should be ignored, not crash"
    rc = cmd_assessbench(target_id="juice-shop", findings=_findings_file(tmp_path, [f]))
    assert rc == 0


def test_assessbench_unknown_target_returns_error(capsys):
    rc = cmd_assessbench(target_id="does-not-exist")
    assert rc == 2


def test_assessbench_no_findings_shows_answer_key(capsys):
    rc = cmd_assessbench(target_id="juice-shop")
    out = capsys.readouterr().out
    assert rc == 0
    assert "/rest/basket/{id}" in out      # ground truth shown
    assert "docker run" in out              # how to provision
