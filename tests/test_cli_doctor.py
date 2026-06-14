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
    rc = cli.cmd_doctor(None, fix=True, yes=True, models=["qwen3:14b"], tools=None)
    out = capsys.readouterr().out
    assert any("qwen3:14b" in c for c in pulled)
    assert "applied" in out.lower() or "done" in out.lower()
