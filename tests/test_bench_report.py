import json
from grin.bench.runner import run_bench
from grin.bench.tasks import default_cases
from grin.bench.report import to_text, to_json

class FixedClient:
    def generate(self, model, system, prompt, temperature=0.2, keep_alive="5m"):
        if "Engagement goal" in prompt:
            return '{"objectives":[{"objective":"enumerate","target":"203.0.113.0/24","action_class":"active-scan"}]}'
        return '{"action":{"tool":"nmap","command":"nmap -sV 203.0.113.7","declared_class":"active-scan"}}'

def _rep():
    return run_bench(FixedClient(), ["m1", "m2"], ["planner", "recon", "exploit"], default_cases())

def test_to_text_shows_roles_models_and_pins():
    txt = to_text(_rep())
    assert "PLANNER" in txt.upper() and "RECON" in txt.upper() and "EXPLOIT" in txt.upper()
    assert "m1" in txt and "m2" in txt
    assert "RECOMMENDED" in txt.upper()
    assert "--planner-model" in txt and "--recon-model" in txt and "--exploit-model" in txt

def test_to_json_round_trips():
    data = json.loads(to_json(_rep()))
    assert "role_results" in data and "recommended_pins" in data
    assert any(r["role"] == "planner" for r in data["role_results"])
