import grin.cli as cli

class FixedClient:
    def generate(self, model, system, prompt, temperature=0.2, keep_alive="5m"):
        if "Engagement goal" in prompt:
            return '{"objectives":[{"objective":"enumerate","target":"203.0.113.0/24","action_class":"active-scan"}]}'
        return '{"action":{"tool":"nmap","command":"nmap -sV 203.0.113.7","declared_class":"active-scan"}}'

def test_bench_cmd_prints_ranking_and_pins(monkeypatch, capsys):
    monkeypatch.setattr(cli, "OllamaClient", lambda *a, **k: FixedClient())
    rc = cli.cmd_bench(models="m1,m2", roles="planner,recon", base_url=None, out=None, json_out=None)
    out = capsys.readouterr().out
    assert rc == 0
    assert "RECOMMENDED" in out.upper() and "m1" in out

def test_bench_cmd_writes_files(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "OllamaClient", lambda *a, **k: FixedClient())
    md = tmp_path / "r.md"; js = tmp_path / "r.json"
    rc = cli.cmd_bench(models="m1", roles="planner", base_url=None,
                       out=str(md), json_out=str(js))
    assert rc == 0 and md.exists() and js.exists()
    assert "RECOMMENDED" in md.read_text().upper()
