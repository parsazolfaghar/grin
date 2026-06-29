from grin.cli import cmd_assess
from grin.finding import Finding


def _F(vc, loc):
    return Finding(title="x", target="http://t", severity="high", evidence="ev",
                   tool="grin-verify", command="c", vuln_class=vc, location=loc)


def test_cmd_assess_prints_findings(monkeypatch, capsys):
    monkeypatch.setattr("grin.engine.run_general", lambda *a, **k: [_F("idor", "/x"), _F("ssrf", "/y")])
    rc = cmd_assess(url="http://t")
    out = capsys.readouterr().out
    assert rc == 0 and "idor" in out and "/x" in out and "ssrf" in out


def test_cmd_assess_no_findings(monkeypatch, capsys):
    monkeypatch.setattr("grin.engine.run_general", lambda *a, **k: [])
    assert cmd_assess(url="http://t") == 0
    assert "no vulnerabilities confirmed" in capsys.readouterr().out


def test_cmd_assess_json(monkeypatch, capsys):
    monkeypatch.setattr("grin.engine.run_general", lambda *a, **k: [_F("xss", "/z")])
    assert cmd_assess(url="http://t", json_out=True) == 0
    assert '"vuln_class": "xss"' in capsys.readouterr().out


def test_cmd_assess_cookie_requires_protected(capsys):
    assert cmd_assess(url="http://t", cookie=True) == 2
    assert "requires --protected" in capsys.readouterr().out


def test_cmd_assess_bench_scores(monkeypatch, capsys):
    monkeypatch.setattr("grin.engine.run_general",
                        lambda *a, **k: [_F("excessive-data-exposure", "/users/v1/_debug")])
    assert cmd_assess(url="http://t", bench="vampi") == 0
    assert "precision" in capsys.readouterr().out.lower()


def test_cmd_assess_creds_and_oob_threaded(monkeypatch, capsys):
    seen = {}

    def fake_run(url, credentials=None, *, request=None, oob=None, **k):
        seen["creds"], seen["oob"] = credentials, oob
        return []
    monkeypatch.setattr("grin.engine.run_general", fake_run)
    # no --oob, so no real OOBServer is started; creds are parsed into login/password dicts
    cmd_assess(url="http://t", creds=["attacker@x:pw1", "victim@x:pw2"])
    assert seen["creds"] == [{"login": "attacker@x", "password": "pw1"},
                             {"login": "victim@x", "password": "pw2"}]
    assert seen["oob"] is None
