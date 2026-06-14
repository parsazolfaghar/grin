from grin.bench.strategies import advisor_prompt, driver_prompt, run_pair, split_pair
from grin.bench.tasks import default_cases
from grin.bench.runner import run_bench
from grin.prompts import parse_step

EXEC = {"objective": "exploit the confirmed SQLi", "target": "www.acme.test",
        "history": "(confirmed)", "allowed": ["exploit"]}


def test_split_pair():
    assert split_pair("a>>b") == ("a", "b")
    assert split_pair("hf.co/x/Model:Q4>>qwen3:14b") == ("hf.co/x/Model:Q4", "qwen3:14b")
    assert split_pair("qwen3:14b") is None


def test_prompts_nonempty_and_driver_carries_recommendation():
    asys, ausr = advisor_prompt(EXEC)
    assert asys and "www.acme.test" in ausr
    dsys, dusr = driver_prompt(EXEC, "use sqlmap -u http://www.acme.test --batch --dump")
    assert dsys and "sqlmap" in dusr and '"action"' in dusr


class PairClient:
    """Advisor returns a free-text technique; driver returns a JSON action."""
    def generate(self, model, system, prompt, temperature=0.0, keep_alive="5m"):
        if "convert" in system.lower():   # driver
            return '{"action": {"tool": "sqlmap", "command": "sqlmap -u http://www.acme.test --dump", "declared_class": "exploit"}}'
        return "Use sqlmap -u http://www.acme.test --batch --dump to extract data."


def test_run_pair_yields_parseable_action():
    raw = run_pair(PairClient(), "advisor", "driver", EXEC)
    dec = parse_step(raw, default_target="www.acme.test")
    assert dec.kind == "action" and dec.action["tool"] == "sqlmap"


def test_runner_pair_path_scores_exploit_case():
    rep = run_bench(PairClient(), ["adv>>drv"], ["exploit"], default_cases(), repeats=1)
    rr = rep.role_result("adv>>drv", "exploit")
    assert rr.n_cases == 5
    # sqlmap is right for sqli (60), offensive-but-not-fit elsewhere (25) -> all parse, none refused
    assert rr.refused_count == 0 and rr.score > 0


def test_runner_pair_on_planner_case_scores_zero():
    # planner case has no exec_inputs -> a pair candidate can't run it
    rep = run_bench(PairClient(), ["adv>>drv"], ["planner"], default_cases(), repeats=1)
    rr = rep.role_result("adv>>drv", "planner")
    assert rr.score == 0.0
