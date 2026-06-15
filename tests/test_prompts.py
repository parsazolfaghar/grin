from grin.prompts import build_step_prompt, parse_step, StepDecision
from grin.finding import Finding
from grin.journal import Journal, Step


def _journal():
    j = Journal(task_id="t", objective="find web services", target="203.0.113.7",
                engagement_path="e.yaml", path="/tmp/j.json")
    j.add_step(Step(action={"tool": "nmap", "command": "nmap -sV 203.0.113.7"},
                    decision="executed", output="80/tcp open http"))
    return j


def test_build_step_prompt_includes_objective_target_history_and_classes():
    sys, usr = build_step_prompt("find web services", "203.0.113.7", _journal(),
                                 ["passive", "active-scan"])
    assert isinstance(sys, str) and sys
    assert "find web services" in usr
    assert "203.0.113.7" in usr
    assert "active-scan" in usr
    assert "nmap -sV 203.0.113.7" in usr      # the history is fed back


def test_parse_step_json_action():
    raw = '{"action": {"tool": "nmap", "command": "nmap -sV 203.0.113.7", ' \
          '"declared_class": "active-scan", "why": "port scan"}}'
    d = parse_step(raw, "203.0.113.7")
    assert d.kind == "action"
    assert d.action["tool"] == "nmap"
    assert d.action["command"] == "nmap -sV 203.0.113.7"
    assert d.action["target"] == "203.0.113.7"     # defaults to task target
    assert d.action["declared_class"] == "active-scan"


def test_parse_step_json_done_with_findings():
    raw = '{"done": true, "findings": [{"title": "WordPress 5.2", "severity": "MEDIUM", ' \
          '"evidence": "x-powered-by", "tool": "whatweb", "command": "whatweb x", ' \
          '"recommendation": "update"}]}'
    d = parse_step(raw, "203.0.113.7")
    assert d.kind == "done"
    assert len(d.findings) == 1
    f = d.findings[0]
    assert isinstance(f, Finding)
    assert f.severity == "medium"               # normalized
    assert f.target == "203.0.113.7"            # defaults to task target
    assert f.title == "WordPress 5.2"


def test_parse_step_done_with_no_findings():
    d = parse_step('{"done": true, "findings": []}', "h")
    assert d.kind == "done"
    assert d.findings == []


def test_parse_step_markdown_action_fallback():
    raw = "Thinking...\nCommand: nmap -sV 203.0.113.7\nWhy: find services"
    d = parse_step(raw, "203.0.113.7")
    assert d.kind == "action"
    assert d.action["command"] == "nmap -sV 203.0.113.7"
    assert d.action["tool"] == "nmap"           # first token of the command
    assert d.action["declared_class"] is None


def test_parse_step_garbage_is_parse_miss():
    d = parse_step("I'm not sure what to do here, sorry!", "h")
    assert d.kind == "parse_miss"


def test_parse_step_done_with_secrets():
    import json
    from grin.prompts import parse_step
    from grin.secret import Secret
    raw = json.dumps({"done": True, "findings": [], "secrets": [
        {"label": "SSH password", "value": "root:toor", "target": "10.0.0.5",
         "tool": "hydra", "command": "hydra ...", "context": "root over ssh"}]})
    d = parse_step(raw, "10.0.0.5")
    assert d.kind == "done"
    assert d.secrets == [Secret(label="SSH password", value="root:toor", target="10.0.0.5",
                                tool="hydra", command="hydra ...", context="root over ssh")]


def test_parse_step_skips_malformed_secret():
    import json
    from grin.prompts import parse_step
    raw = json.dumps({"done": True, "findings": [],
                      "secrets": [{"label": "x"}, {"value": "y"}]})
    d = parse_step(raw, "h")
    assert d.secrets == []


def test_parse_step_no_secrets_key():
    import json
    from grin.prompts import parse_step
    d = parse_step(json.dumps({"done": True, "findings": []}), "h")
    assert d.secrets == []


def test_build_step_prompt_documents_secrets_format():
    from grin.prompts import build_step_prompt
    from grin.journal import Journal
    j = Journal(task_id="t", objective="o", target="127.0.0.1", engagement_path="e", path="/tmp/j.json")
    sys, usr = build_step_prompt("o", "127.0.0.1", j, ["passive", "active-scan"])
    assert "secrets" in usr.lower()        # the model is told how to report captured secrets
    assert "value" in usr.lower()


def test_step_prompt_has_no_parroted_nmap_example_and_guides_exploitation():
    from grin.prompts import build_step_prompt
    from grin.journal import Journal
    j = Journal(task_id="t", objective="o", target="10.0.0.1", engagement_path="e",
                path="/tmp/j", max_steps=12)
    system, user = build_step_prompt("capture the flag", "10.0.0.1", j, ["active-scan", "exploit"])
    blob = (system + "\n" + user).lower()
    # no runnable nmap -sV <target> example to parrot
    assert "nmap -sv 10.0.0.1" not in blob
    # phase/exploitation guidance present
    assert "exploit" in blob
    # anti-repeat guidance present
    assert "repeat" in blob or "already" in blob
    # the JSON action schema key is still documented (parse_step contract intact)
    assert '"action"' in user and '"done"' in user
