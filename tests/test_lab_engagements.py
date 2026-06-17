from grin.lab.answers import Target
from grin.lab.engagements import engagement_dict


def _t():
    return Target(id="t2-web", container="grin-lab-web", ip="172.30.0.12", tier="medium",
                  open_ports=[80], vuln_class="command-injection",
                  expected_findings=["command injection"], flag="GRIN{x}", win="flag-in-loot")


def test_engagement_dict_shape():
    d = engagement_dict(_t(), runner_container="grin-kali")
    assert d["id"] == "lab-t2-web"
    assert d["mode"] == "own-lab"
    assert d["scope"]["in"] == ["172.30.0.12"]
    assert "exploit" in d["roe"]["allowed_actions"]
    assert d["env"] == {"kind": "docker", "container": "grin-kali"}
    assert d["state"] == "active"
    assert d["audit_log"] == "./audit/lab-t2-web.jsonl"


def test_engagement_dict_is_loadable(tmp_path):
    import yaml
    from grin.engagement import load_engagement
    d = engagement_dict(_t(), runner_container="grin-kali")
    p = tmp_path / "lab-t2.yaml"
    p.write_text(yaml.safe_dump(d))
    eng = load_engagement(str(p))
    assert eng.id == "lab-t2-web"
    assert eng.scope.include == ["172.30.0.12"]


def test_engagement_scope_includes_extra_scope():
    # T6's pivot vault must be in scope so lateral movement is authorized.
    t6 = Target(id="t6-pivot", container="grin-lab-pivot-web", ip="172.30.0.16", tier="master",
                open_ports=[80], vuln_class="lateral-movement",
                expected_findings=["lateral movement"], flag="GRIN{z}", win="flag-in-loot",
                extra_scope=["172.30.0.17"])
    d = engagement_dict(t6)
    assert d["scope"]["in"] == ["172.30.0.16", "172.30.0.17"]
