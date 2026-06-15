from pathlib import Path
from grin.catalog import load_catalog, tool_to_techniques

CATALOG = str(Path(__file__).resolve().parents[1] / "catalog" / "attack_catalog.yaml")


def test_shipped_catalog_loads():
    techs = load_catalog(CATALOG)
    assert len(techs) >= 8
    for t in techs:
        assert t.id.startswith("T") and t.tools


def test_shipped_catalog_covers_core_tactics():
    techs = load_catalog(CATALOG)
    tactics = {t.tactic for t in techs}
    for needed in ("reconnaissance", "credential-access", "initial-access",
                   "privilege-escalation", "discovery"):
        assert needed in tactics, needed


def test_shipped_catalog_has_no_impact_tactic():
    techs = load_catalog(CATALOG)
    assert all(t.tactic != "impact" for t in techs)


def test_shipped_catalog_maps_lab_tools():
    m = tool_to_techniques(load_catalog(CATALOG))
    assert "nmap" in m and "hydra" in m
