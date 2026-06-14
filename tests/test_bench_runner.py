from grin.bench.runner import run_bench, BenchReport
from grin.bench.tasks import default_cases

class ScriptClient:
    """Returns a reply chosen by (model, prompt-substring); records calls."""
    def __init__(self, table): self.table = table; self.calls = []
    def generate(self, model, system, prompt, temperature=0.2, keep_alive="5m"):
        self.calls.append(model)
        for (m, needle), reply in self.table.items():
            if m == model and needle in prompt:
                return reply
        return "no idea"

GOOD_PLAN = '{"objectives":[{"objective":"enumerate","target":"203.0.113.0/24","action_class":"active-scan"}]}'
GOOD_ACTION = '{"action":{"tool":"nmap","command":"nmap -sV 203.0.113.7","declared_class":"active-scan"}}'
REFUSAL = "I'm sorry, I cannot assist with that. As an AI it would be unethical."

def test_run_bench_ranks_models_per_role():
    table = {
        ("good", "Engagement goal"): GOOD_PLAN,
        ("good", "Decide the SINGLE next action"): GOOD_ACTION,
        ("bad", "Engagement goal"): "prose no json",
        ("bad", "Decide the SINGLE next action"): REFUSAL,
    }
    rep = run_bench(ScriptClient(table), ["good", "bad"], ["planner", "recon", "exploit"],
                    default_cases())
    assert isinstance(rep, BenchReport)
    planner_rank = rep.ranking("planner")
    assert planner_rank[0][0] == "good"           # (model, score) sorted desc
    # 'bad' refuses the exploit case
    bad_exploit = rep.role_result("bad", "exploit")
    assert bad_exploit.refused is True

def test_recommended_pin_picks_winner_per_role():
    table = {("good", "Engagement goal"): GOOD_PLAN,
             ("good", "Decide the SINGLE next action"): GOOD_ACTION}
    rep = run_bench(ScriptClient(table), ["good"], ["planner", "recon"], default_cases())
    pins = rep.recommended_pins()
    assert pins["planner"] == "good" and pins["recon"] == "good"

def test_client_error_scores_zero_not_crash():
    class Boom:
        def generate(self, *a, **k): raise RuntimeError("model down")
    rep = run_bench(Boom(), ["x"], ["planner"], default_cases())
    assert rep.role_result("x", "planner").score == 0
