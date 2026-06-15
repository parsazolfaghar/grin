import pytest
from grin.catalog import (Technique, CatalogError, load_catalog, applies,
                          techniques_for, tool_to_techniques)
from grin.services import Service


def _yaml(tmp_path, body):
    p = tmp_path / "cat.yaml"
    p.write_text(body)
    return str(p)


VALID = """
techniques:
  - {id: T1595, tactic: reconnaissance, name: Active Scanning, action_class: active-scan,
     tools: [nmap], command_templates: ["nmap -sV {target}"], applies_when: always}
  - {id: T1110, tactic: credential-access, name: Brute Force, action_class: exploit,
     tools: [hydra], command_templates: ["hydra ssh://{target}"], applies_when: "port:22"}
  - {id: T1190, tactic: initial-access, name: Exploit Public-Facing App, action_class: exploit,
     tools: [curl, sqlmap], command_templates: ["curl http://{target}/"], applies_when: "service:http"}
"""


def test_load_valid(tmp_path):
    techs = load_catalog(_yaml(tmp_path, VALID))
    assert len(techs) == 3
    t = techs[0]
    assert isinstance(t, Technique)
    assert t.id == "T1595" and t.action_class == "active-scan" and t.tools == ["nmap"]


def test_bad_action_class_raises(tmp_path):
    bad = """
techniques:
  - {id: T1, tactic: x, name: n, action_class: nuke, tools: [a], command_templates: [], applies_when: always}
"""
    with pytest.raises(CatalogError):
        load_catalog(_yaml(tmp_path, bad))


def test_missing_field_raises(tmp_path):
    bad = "techniques:\n  - {id: T1, tactic: x}\n"
    with pytest.raises(CatalogError):
        load_catalog(_yaml(tmp_path, bad))


def test_empty_raises(tmp_path):
    with pytest.raises(CatalogError):
        load_catalog(_yaml(tmp_path, "techniques: []\n"))


def test_applies_always_port_service():
    t_always = Technique("T1", "x", "n", "active-scan", ["nmap"], ["c"], "always")
    t_port = Technique("T2", "x", "n", "exploit", ["hydra"], ["c"], "port:22")
    t_svc = Technique("T3", "x", "n", "exploit", ["curl"], ["c"], "service:http")
    svcs = [Service(22, "ssh"), Service(80, "http")]
    assert applies(t_always, svcs) is True
    assert applies(t_always, []) is True
    assert applies(t_port, svcs) is True
    assert applies(t_port, [Service(80, "http")]) is False
    assert applies(t_svc, svcs) is True
    assert applies(t_svc, [Service(22, "ssh")]) is False


def test_techniques_for_filters(tmp_path):
    techs = load_catalog(_yaml(tmp_path, VALID))
    got = techniques_for(techs, [Service(22, "ssh")])
    ids = {t.id for t in got}
    assert "T1595" in ids and "T1110" in ids and "T1190" not in ids


def test_tool_to_techniques(tmp_path):
    techs = load_catalog(_yaml(tmp_path, VALID))
    m = tool_to_techniques(techs)
    assert m["nmap"] == ["T1595"]
    assert "T1190" in m["curl"] and "T1190" in m["sqlmap"]
