import json
from grin.medic import triage, MedicDecision
from grin.inference import FakeClient
from grin.objective import Objective


def test_triage_concludes_with_diagnosis():
    reply = json.dumps({"action": "conclude",
                        "diagnosis": "Reached RCE on .12 but never read the flag path."})
    d = triage(FakeClient(reply), "m", goal="g", findings=[], secrets=[],
               tried_objectives=[Objective("scan", "t")], recent_steps=[], scope_targets=["t"])
    assert isinstance(d, MedicDecision)
    assert d.action == "conclude"
    assert "RCE" in d.diagnosis
    assert d.objectives == []


def test_triage_failsoft_on_garbage_concludes():
    d = triage(FakeClient("not json at all"), "m", goal="g", findings=[], secrets=[],
               tried_objectives=[], recent_steps=[], scope_targets=["t"])
    assert d.action == "conclude" and d.diagnosis  # non-empty, did not raise


def test_triage_recovers_with_new_objectives():
    reply = json.dumps({"action": "recover", "objectives": [
        {"objective": "read /flag.txt via the existing RCE", "target": "172.30.0.12",
         "action_class": "exploit"}]})
    d = triage(FakeClient(reply), "m", goal="capture flag", findings=[], secrets=[],
               tried_objectives=[Objective("exploit cmd injection", "172.30.0.12")],
               recent_steps=[{"objective": "exploit cmd injection", "command": "curl ...;id",
                              "exit_code": 0, "output": "uid=33(www-data)", "extracted": []}],
               scope_targets=["172.30.0.12"])
    assert d.action == "recover"
    assert len(d.objectives) == 1
    assert d.objectives[0].target == "172.30.0.12"
    assert "flag" in d.objectives[0].objective


def test_propose_patch_drafts_a_proposal():
    from grin.medic import propose_patch
    out = propose_patch(FakeClient("## Proposal\nAdd a regex to grin/extractors.py for JWT tokens."),
                        "m", diagnosis="found a JWT in output but it was never captured as loot",
                        goal="capture creds")
    assert "extractors.py" in out


def test_triage_conclude_with_patches_populates_patch_field():
    reply = json.dumps({"action": "conclude", "diagnosis": "no extractor for the loot type seen"})
    d = triage(FakeClient([reply, "## Patch proposal\nadd extractor X"]), "m", goal="g",
               findings=[], secrets=[], tried_objectives=[], recent_steps=[], scope_targets=["t"],
               propose_patches=True)
    assert d.action == "conclude"
    assert d.patch and "extractor" in d.patch


def test_triage_conclude_without_patches_leaves_patch_empty():
    reply = json.dumps({"action": "conclude", "diagnosis": "stuck"})
    d = triage(FakeClient(reply), "m", goal="g", findings=[], secrets=[], tried_objectives=[],
               recent_steps=[], scope_targets=["t"])   # propose_patches defaults False
    assert d.action == "conclude" and d.patch == ""


def test_triage_recover_does_not_propose_patch():
    reply = json.dumps({"action": "recover", "objectives": [
        {"objective": "read flag", "target": "t", "action_class": "exploit"}]})
    d = triage(FakeClient(reply), "m", goal="g", findings=[], secrets=[], tried_objectives=[],
               recent_steps=[], scope_targets=["t"], propose_patches=True)
    assert d.action == "recover" and d.patch == ""   # only conclude proposes a patch


def test_triage_recover_that_only_repeats_tried_concludes():
    tried = [Objective("scan ports", "t")]
    reply = json.dumps({"action": "recover",
                        "objectives": [{"objective": "scan ports", "target": "t",
                                        "action_class": "active-scan"}],
                        "diagnosis": "only re-proposed a tried objective"})
    d = triage(FakeClient(reply), "m", goal="g", findings=[], secrets=[],
               tried_objectives=tried, recent_steps=[], scope_targets=["t"])
    assert d.action == "conclude"  # nothing genuinely new -> conclude, not loop
