import json
from grin.analyst import initial_plan, replan, AnalystDecision, _render_secrets
from grin.objective import Objective
from grin.inference import FakeClient
from grin.finding import Finding
from grin.secret import Secret


def test_render_secrets_compacts_multiline_private_key():
    """A captured private key must register so the planner knows we have it, but its multi-line PEM
    body must not be dumped into the prompt — render one compact line per secret."""
    key = Secret(label="private key",
                 value="-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\nCCCC\n-----END OPENSSH PRIVATE KEY-----",
                 target="172.30.0.16", tool="curl", command="curl ...")
    rendered = _render_secrets([key])
    assert rendered.count("\n") == 0          # exactly one line for the one secret
    assert "private key" in rendered           # the planner still learns we hold a key
    assert "AAAA" not in rendered              # raw key body is not leaked into the prompt
    assert "172.30.0.16" in rendered


def test_render_secrets_keeps_short_values_intact():
    """Short secrets (creds/flags) render verbatim — only long/multiline values are compacted."""
    cred = Secret(label="cracked password", value="hunter2", target="t", tool="john", command="c")
    assert "hunter2" in _render_secrets([cred])


def test_initial_plan_parses_objectives():
    reply = json.dumps({"objectives": [
        {"objective": "enumerate hosts", "target": "203.0.113.0/24"},
        {"objective": "scan web", "target": "203.0.113.7"},
    ]})
    plan = initial_plan(FakeClient(reply), "m", "assess network", ["203.0.113.0/24"], [])
    assert plan == [Objective("enumerate hosts", "203.0.113.0/24"),
                    Objective("scan web", "203.0.113.7")]


def test_initial_plan_uses_seeds_in_prompt_and_still_parses():
    reply = json.dumps({"objectives": [{"objective": "scan", "target": "10.0.0.5"}]})
    plan = initial_plan(FakeClient(reply), "m", "assess", ["10.0.0.0/24"], ["10.0.0.5"])
    assert plan == [Objective("scan", "10.0.0.5")]


def test_initial_plan_parse_miss_returns_empty():
    assert initial_plan(FakeClient("no json here"), "m", "g", ["x"], []) == []


def test_initial_plan_skips_items_missing_fields():
    reply = json.dumps({"objectives": [
        {"objective": "ok", "target": "h"},
        {"objective": "", "target": "h"},
        {"objective": "no target"},
    ]})
    plan = initial_plan(FakeClient(reply), "m", "g", ["h"], [])
    assert plan == [Objective("ok", "h")]


def test_replan_parses_followups_and_done_false():
    reply = json.dumps({"done": False, "reason": "found a login page",
                        "next_objectives": [{"objective": "brute login", "target": "203.0.113.7"}]})
    d = replan(FakeClient(reply), "m", "goal", [], 1, 0, ["203.0.113.0/24"])
    assert isinstance(d, AnalystDecision)
    assert d.done is False
    assert d.reason == "found a login page"
    assert d.next_objectives == [Objective("brute login", "203.0.113.7")]


def test_replan_done_true():
    reply = json.dumps({"done": True, "reason": "goal met", "next_objectives": []})
    d = replan(FakeClient(reply), "m", "goal", [Finding("t", "h", "low", "e", "nmap", "c")], 3, 0,
               ["192.168.1.0/24"])
    assert d.done is True
    assert d.next_objectives == []


def test_replan_parse_miss_is_fail_soft():
    d = replan(FakeClient("garbage"), "m", "goal", [], 1, 0, ["10.10.0.0/16"])
    assert d.done is False
    assert d.next_objectives == []
    assert "unparseable" in d.reason


class _RecordingClient:
    def __init__(self, reply):
        self.reply = reply
        self.prompt = ""

    def is_up(self):
        return True

    def installed_models(self):
        return []

    def generate(self, model, system, prompt, temperature=0.3, keep_alive="10m"):
        self.prompt = prompt
        return self.reply


def test_replan_prompt_includes_captured_secrets():
    from grin.secret import Secret
    rec = _RecordingClient(json.dumps({"done": True, "reason": "flag", "next_objectives": []}))
    flag = Secret(label="flag", value="GRIN{abc123}", target="10.0.0.5", tool="curl",
                  command="curl x", context="captured")
    d = replan(rec, "m", "capture the flag", [], 1, 0, ["10.0.0.0/24"], secrets=[flag])
    assert "GRIN{abc123}" in rec.prompt           # the analyst is shown the captured flag
    assert "Secrets/flags captured" in rec.prompt
    assert d.done is True


def test_initial_plan_parses_action_class():
    import json
    from grin.analyst import initial_plan
    from grin.inference import FakeClient
    reply = json.dumps({"objectives": [
        {"objective": "enumerate", "target": "h", "action_class": "active-scan"},
        {"objective": "exploit it", "target": "h", "action_class": "exploit"},
    ]})
    plan = initial_plan(FakeClient(reply), "m", "g", ["h"], [])
    assert plan[0].action_class == "active-scan"
    assert plan[1].action_class == "exploit"


def test_initial_plan_invalid_or_absent_action_class_defaults_empty():
    import json
    from grin.analyst import initial_plan
    from grin.inference import FakeClient
    reply = json.dumps({"objectives": [
        {"objective": "a", "target": "h", "action_class": "bogus"},
        {"objective": "b", "target": "h"},
    ]})
    plan = initial_plan(FakeClient(reply), "m", "g", ["h"], [])
    assert plan[0].action_class == ""
    assert plan[1].action_class == ""


def test_replan_parses_action_class():
    import json
    from grin.analyst import replan
    from grin.inference import FakeClient
    reply = json.dumps({"done": False, "reason": "r",
                        "next_objectives": [{"objective": "x", "target": "h",
                                             "action_class": "exploit"}]})
    d = replan(FakeClient(reply), "m", "g", [], 1, 0, ["h"])
    assert d.next_objectives[0].action_class == "exploit"


def test_replan_prompt_biases_toward_exploitation():
    """replan's USER prompt must mention exploitation so small models parrot exploit, not scan."""
    captured = {}

    class CapturingClient:
        def is_up(self):
            return True

        def generate(self, model, system, prompt, temperature=0.3, keep_alive="10m"):
            captured["system"] = system
            captured["prompt"] = prompt
            return '{"done": false, "reason": "x", "next_objectives": []}'

    from grin.analyst import replan
    replan(CapturingClient(), "m", "capture the flag", [], 1, 0, ["192.168.50.0/24"])
    blob = captured["prompt"].lower()
    # The user prompt must explicitly guide toward exploitation
    assert "exploit" in blob
    # The example action_class in the replan template must be exploit, NOT active-scan
    # (so parroting small models default to exploit, not recon)
    assert '"action_class": "exploit"' in captured["prompt"] or \
           '"action_class":"exploit"' in captured["prompt"]


def test_replan_prompt_includes_scope_and_no_fake_ip():
    """replan's prompt must include the in-scope targets and must NOT contain hardcoded fake IPs."""
    captured = {}

    class CapturingClient:
        def is_up(self):
            return True

        def generate(self, model, system, prompt, temperature=0.3, keep_alive="10m"):
            captured["p"] = prompt
            return '{"done":false,"reason":"x","next_objectives":[]}'

    from grin.analyst import replan
    replan(CapturingClient(), "m", "goal", [], 1, 0, ["172.30.0.11"])
    assert "172.30.0.11" in captured["p"]
    assert "10.0.0.5" not in captured["p"] and "203.0.113" not in captured["p"]


def test_initial_plan_example_has_no_concrete_fake_ip():
    """initial_plan's JSON example must NOT contain concrete fake IPs that models can parrot."""
    captured = {}

    class CapturingClient:
        def is_up(self):
            return True

        def generate(self, model, system, prompt, temperature=0.3, keep_alive="10m"):
            captured["p"] = prompt
            return '{"objectives": []}'

    from grin.analyst import initial_plan
    initial_plan(CapturingClient(), "m", "find the flag", ["10.10.0.0/24"], [])
    # The example block must not contain concrete routable IPs from the old template
    assert "203.0.113.0/24" not in captured["p"]
    assert "203.0.113.5" not in captured["p"]


def test_initial_plan_prompt_mentions_exploitation_goal():
    """initial_plan's USER prompt must include an exploit-class example AND explicit guidance that
    recon leads toward exploitation — not just list 'exploit' in the enum."""
    captured = {}

    class CapturingClient:
        def is_up(self):
            return True

        def generate(self, model, system, prompt, temperature=0.3, keep_alive="10m"):
            captured["prompt"] = prompt
            return '{"objectives": []}'

    from grin.analyst import initial_plan
    initial_plan(CapturingClient(), "m", "capture the flag", ["10.0.0.1"], [])
    prompt = captured["prompt"]
    # The schema example must include an exploit-class objective (not only active-scan)
    assert '"action_class": "exploit"' in prompt or '"action_class":"exploit"' in prompt
    # The guidance text must explicitly direct toward exploitation as the goal of recon
    assert "exploit" in prompt.lower()


# --- SP2: assessment-mode planning (uses the existing _RecordingClient above) ---

def test_initial_plan_assessment_prompt_targets_access_control():
    c = _RecordingClient(json.dumps({"objectives": []}))
    initial_plan(c, "m", "assess the app", ["http://t/"], [], mode="assessment")
    p = c.prompt.lower()
    assert "bac-probe" in p and "access control" in p
    assert "capture the flag" not in p


def test_initial_plan_ctf_mode_unchanged():
    c = _RecordingClient(json.dumps({"objectives": []}))
    initial_plan(c, "m", "g", ["t"], [])          # default ctf
    p = c.prompt.lower()
    assert "exploit" in p and "bac-probe" not in p


def test_replan_assessment_prompt_drops_flag_framing():
    c = _RecordingClient(json.dumps({"done": True, "next_objectives": []}))
    replan(c, "m", "assess", [], 1, 0, ["http://t/"], mode="assessment")
    p = c.prompt.lower()
    assert "access-control" in p
    assert "capture the flag" not in p


def test_replan_ctf_mode_unchanged():
    c = _RecordingClient(json.dumps({"done": False, "next_objectives": []}))
    replan(c, "m", "g", [], 0, 1, ["t"])          # default ctf
    assert "flag" in c.prompt.lower()
