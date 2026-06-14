import grin.cli as cli
from grin.orchestrator import EngagementResult
from grin.finding import Finding
from grin.report_store import save_result, result_path
from grin.engagement import load_engagement

EXAMPLE = """
id: t-hp
name: hp
mode: own-lab
scope: {{include: ["127.0.0.1"], exclude: []}}
roe: {{allowed_actions: ["passive","active-scan"], windows: []}}
autonomy: autonomous
env: {{kind: local}}
audit_log: "{audit}"
state: active
"""


def _eng(tmp_path):
    audit = str(tmp_path / "a.jsonl")
    f = tmp_path / "t-hp.yaml"
    f.write_text(EXAMPLE.format(audit=audit))
    return str(f)


def test_honeypot_cmd_flags_fingerprint(tmp_path, capsys):
    path = _eng(tmp_path)
    eng = load_engagement(path)
    res = EngagementResult(status="completed", findings=[
        Finding("SSH", "127.0.0.1", "info", "banner: Cowrie SSH honeypot", "nmap", "nmap", "")])
    save_result(result_path(eng), res)
    rc = cli.cmd_honeypot(path)
    out = capsys.readouterr().out
    assert rc == 0
    assert "SUSPECTED" in out and "cowrie" in out.lower()
    assert "advisory only" in out.lower()


def test_honeypot_cmd_clear_when_no_signals(tmp_path, capsys):
    path = _eng(tmp_path)
    eng = load_engagement(path)
    save_result(result_path(eng), EngagementResult(status="completed", findings=[
        Finding("SSH", "127.0.0.1", "info", "22/tcp open ssh OpenSSH 10.3", "nmap", "nmap", "")]))
    rc = cli.cmd_honeypot(path)
    out = capsys.readouterr().out
    assert rc == 0 and "clear" in out
