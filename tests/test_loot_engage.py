import json
from datetime import datetime
from grin.orchestrator import orchestrate
from grin.engagement import validate_engagement
from grin.inference import FakeClient
from grin.runner import FakeRunner, ExecResult
from grin.loot import LootStore, loot_dir

NOW = datetime(2026, 1, 1)

def make_eng(tmp_path):
    return validate_engagement({"id":"e1","name":"n","mode":"own-lab",
        "scope":{"in":["127.0.0.1"]},"roe":{"allowed_actions":["passive","active-scan","exploit"]},
        "autonomy":"autonomous","env":{"kind":"local"},
        "audit_log":str(tmp_path/"audit"/"e1.jsonl"),"state":"active"})

def _plan(o,t): return json.dumps({"objectives":[{"objective":o,"target":t,"action_class":"active-scan"}]})
def _act(c): return json.dumps({"action":{"tool":"nmap","command":c,"target":"127.0.0.1","declared_class":"active-scan","why":"x"}})
def _done_secret(): return json.dumps({"done":True,"findings":[],"secrets":[
    {"label":"SSH password","value":"root:toor","target":"127.0.0.1","tool":"nmap","command":"c","context":"root"}]})

def test_orchestrate_collects_and_writes_loot(tmp_path):
    eng = make_eng(tmp_path)
    planner = FakeClient([_plan("enum","127.0.0.1"), json.dumps({"done":True,"reason":"d","next_objectives":[]})])
    executor = FakeClient([_act("nmap 127.0.0.1"), _done_secret()])
    runner = FakeRunner({"nmap 127.0.0.1": ExecResult("ok",0,0.1,False)})
    res = orchestrate(eng, goal="g", planner_client=planner, executor_client=executor,
                      runner=runner, now=NOW, max_objectives=3, engagement_path=str(tmp_path/"e.yaml"))
    assert len(res.secrets) == 1 and res.secrets[0].value == "root:toor"
    rows = LootStore(loot_dir(eng)).all()
    assert len(rows) == 1 and rows[0]["value"] == "root:toor" and rows[0]["objective"] == "enum"
