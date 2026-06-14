import json
from datetime import datetime
from ronin.orchestrator import orchestrate, _model_for, EngagementResult
from ronin.objective import Objective
from ronin.engagement import validate_engagement
from ronin.inference import FakeClient
from ronin.runner import FakeRunner

NOW = datetime(2026, 1, 1)


def make_eng(tmp_path, **over):
    d = {
        "id": "e1", "name": "n", "mode": "own-lab",
        "scope": {"in": ["127.0.0.1"], "exclude": []},
        "roe": {"allowed_actions": ["passive", "active-scan", "exploit"], "windows": []},
        "autonomy": "autonomous", "env": {"kind": "local"},
        "audit_log": str(tmp_path / "audit" / "e1.jsonl"), "state": "active",
    }
    d.update(over)
    return validate_engagement(d)


class RecModel(FakeClient):
    def __init__(self, replies):
        super().__init__(replies)
        self.models = []

    def generate(self, model, system, prompt, temperature=0.3, keep_alive="10m"):
        self.models.append(model)
        return super().generate(model=model, system=system, prompt=prompt,
                                temperature=temperature, keep_alive=keep_alive)


def test_model_for_routes_by_action_class():
    omap = {"passive": "M_recon", "active-scan": "M_recon",
            "exploit": "M_exploit", "post-exploit": "M_exploit"}
    assert _model_for(Objective("o", "h", "active-scan"), omap, "BASE") == "M_recon"
    assert _model_for(Objective("o", "h", "exploit"), omap, "BASE") == "M_exploit"
    assert _model_for(Objective("o", "h", ""), omap, "BASE") == "BASE"
    assert _model_for(Objective("o", "h", "passive"), None, "BASE") == "BASE"


def _plan(objs):
    return json.dumps({"objectives": [{"objective": o, "target": t, "action_class": c}
                                      for o, t, c in objs]})


def _replan(done, objs=(), reason="r"):
    return json.dumps({"done": done, "reason": reason,
                       "next_objectives": [{"objective": o, "target": t, "action_class": c}
                                           for o, t, c in objs]})


def _ex_done(findings):
    return json.dumps({"done": True, "findings": findings})


def test_orchestrate_routes_objectives_to_per_class_models(tmp_path):
    eng = make_eng(tmp_path)
    planner = RecModel([
        _plan([("enumerate", "127.0.0.1", "active-scan"), ("exploit", "127.0.0.1", "exploit")]),
        _replan(False, [], "continue"),
        _replan(True, [], "done"),
    ])
    executor = RecModel([_ex_done([]), _ex_done([])])
    omap = {"passive": "M_recon", "active-scan": "M_recon",
            "exploit": "M_exploit", "post-exploit": "M_exploit"}
    res = orchestrate(eng, goal="g", planner_client=planner, executor_client=executor,
                      runner=FakeRunner(), now=NOW, model="BASE", planner_model="M_plan",
                      objective_models=omap, max_objectives=5)
    assert res.status == "completed"
    assert executor.models == ["M_recon", "M_exploit"]
    assert set(planner.models) == {"M_plan"}


def test_orchestrate_no_overrides_uses_base_model(tmp_path):
    eng = make_eng(tmp_path)
    planner = RecModel([_plan([("enumerate", "127.0.0.1", "active-scan")]), _replan(True, [], "done")])
    executor = RecModel([_ex_done([])])
    res = orchestrate(eng, goal="g", planner_client=planner, executor_client=executor,
                      runner=FakeRunner(), now=NOW, model="BASE", max_objectives=5)
    assert res.status == "completed"
    assert executor.models == ["BASE"]
    assert set(planner.models) == {"BASE"}
