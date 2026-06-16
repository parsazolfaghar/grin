import json
from grin.cli import cmd_engage, build_parser
import grin.cli as cli
from grin.inference import FakeClient
from grin.runner import FakeRunner

ENG_YAML = """
id: e1
name: n
mode: own-lab
scope:
  in: ["127.0.0.1"]
roe:
  allowed_actions: [passive, active-scan, exploit]
autonomy: autonomous
env: {{kind: local}}
audit_log: {audit}
state: active
"""


def _write_eng(tmp_path):
    audit = str(tmp_path / "audit" / "e1.jsonl")
    p = tmp_path / "e1.yaml"
    p.write_text(ENG_YAML.format(audit=audit))
    return str(p)


class RecModel(FakeClient):
    def __init__(self, replies):
        super().__init__(replies)
        self.models = []

    def generate(self, model, system, prompt, temperature=0.3, keep_alive="10m"):
        self.models.append(model)
        return super().generate(model=model, system=system, prompt=prompt,
                                temperature=temperature, keep_alive=keep_alive)


def test_model_flags_parse():
    args = build_parser().parse_args(
        ["engage", "e.yaml", "--goal", "g", "--planner-model", "P",
         "--recon-model", "R", "--exploit-model", "X"])
    assert args.planner_model == "P"
    assert args.recon_model == "R"
    assert args.exploit_model == "X"


def test_cmd_engage_builds_map_and_routes(tmp_path, monkeypatch):
    path = _write_eng(tmp_path)
    planner = RecModel([
        json.dumps({"objectives": [{"objective": "enumerate", "target": "127.0.0.1",
                                    "action_class": "active-scan"}]}),
        json.dumps({"done": True, "reason": "done", "next_objectives": []}),
    ])
    executor = RecModel([json.dumps({"done": True, "findings": []})])
    monkeypatch.setattr(cli, "_make_client", lambda eng: planner)
    monkeypatch.setattr(cli, "_make_executor_client", lambda eng: executor)
    monkeypatch.setattr(cli, "_runner_for", lambda eng: FakeRunner())
    rc = cmd_engage(path, goal="g", seeds="", model="BASE", planner_model="P",
                    recon_model="R", exploit_model="X", max_objectives=5, max_steps=6)
    assert rc == 0
    assert executor.models == ["R"]
    assert set(planner.models) == {"P"}
