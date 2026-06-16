import grin.cli as cli
from grin.inference import FakeClient

def test_doctor_no_file_reports_and_exit_ok(monkeypatch, capsys):
    # all good: Ollama up, default model present
    monkeypatch.setattr(cli, "OllamaClient", lambda *a, **k: FakeClient(up=True, models=[cli.DEFAULT_MODEL]))
    rc = cli.cmd_doctor(None, fix=False, yes=False, models=None, tools=None)
    out = capsys.readouterr().out
    assert "[OK]" in out and "OS" in out
    assert rc == 0

def test_doctor_reports_missing_model_nonzero(monkeypatch, capsys):
    monkeypatch.setattr(cli, "OllamaClient", lambda *a, **k: FakeClient(up=True, models=[]))
    rc = cli.cmd_doctor(None, fix=False, yes=False, models=["qwen3:14b"], tools=None)
    out = capsys.readouterr().out
    assert "[MISSING]" in out
    assert rc == 1

def test_doctor_fix_yes_pulls_missing_model(monkeypatch, capsys):
    monkeypatch.setattr(cli, "OllamaClient", lambda *a, **k: FakeClient(up=True, models=[]))
    pulled = []
    monkeypatch.setattr(cli, "_run_ollama_pull", lambda cmd: (pulled.append(cmd) or ("done", True)))
    cli.cmd_doctor(None, fix=True, yes=True, models=["qwen3:14b"], tools=None)
    out = capsys.readouterr().out
    assert any("qwen3:14b" in c for c in pulled)
    assert "applied" in out.lower() or "done" in out.lower()


def test_doctor_with_engagement_file_adds_env_and_tool_checks(monkeypatch, capsys):
    # With an engagement file, cmd_doctor must build a runner and probe env + arsenal tools.
    from grin.engagement import Engagement, Scope, ROE
    from grin.runner import FakeRunner, ExecResult

    eng = Engagement(id="e", name="e", mode="own-lab", scope=Scope(["127.0.0.1"], []),
                     roe=ROE(["passive"], []), autonomy="autonomous", env={"kind": "local"},
                     audit_log="/tmp/a.jsonl", state="active")
    monkeypatch.setattr(cli, "OllamaClient", lambda *a, **k: FakeClient(up=True, models=[cli.DEFAULT_MODEL]))
    monkeypatch.setattr(cli, "load_engagement", lambda p: eng)
    # nmap present in the env -> a "[OK] ... tool: nmap" line must appear
    monkeypatch.setattr(cli, "build_runner",
                        lambda env: FakeRunner({"command -v nmap": ExecResult("/usr/bin/nmap", 0, 0.0, False)}))
    rc = cli.cmd_doctor("eng.yaml", fix=False, yes=False, models=None, tools=None)
    out = capsys.readouterr().out
    assert "tool: nmap" in out
    assert "env: local" in out
    assert rc == 0
