from grin.catalog import load_catalog
from grin.aggressive import DEFAULT_AGGRESSIVE_BUDGET, sweep_objectives, discovered_services
from grin.services import Service
from grin.finding import Finding
from pathlib import Path

CAT = str(Path(__file__).resolve().parents[1] / "catalog" / "attack_catalog.yaml")


def test_budget_constants():
    assert DEFAULT_AGGRESSIVE_BUDGET["max_objectives"] >= 16
    assert DEFAULT_AGGRESSIVE_BUDGET["max_steps"] >= 40


def test_sweep_no_services_yields_always_techniques():
    cat = load_catalog(CAT)
    objs = sweep_objectives(cat, ["10.0.0.5"], {})
    assert objs, "expected always-applicable recon objectives"
    assert all(o.target == "10.0.0.5" for o in objs)
    assert any(o.objective.startswith("[T1595") for o in objs)


def test_sweep_with_ssh_service_adds_brute_force():
    cat = load_catalog(CAT)
    objs = sweep_objectives(cat, ["10.0.0.5"], {"10.0.0.5": [Service(22, "ssh")]})
    ids = [o.objective.split()[0] for o in objs]
    assert any(s.startswith("[T1110") for s in ids)


def test_sweep_per_target():
    cat = load_catalog(CAT)
    objs = sweep_objectives(cat, ["10.0.0.5", "10.0.0.6"], {})
    targets = {o.target for o in objs}
    assert targets == {"10.0.0.5", "10.0.0.6"}


def test_discovered_services_from_nmap_findings():
    findings = [
        Finding(title="ports", target="10.0.0.5", severity="info",
                evidence="22/tcp open ssh OpenSSH\n80/tcp open http nginx",
                tool="nmap", command="nmap -sV 10.0.0.5"),
        Finding(title="other", target="10.0.0.5", severity="info",
                evidence="irrelevant", tool="hydra", command="hydra ..."),
    ]
    svcs = discovered_services(findings)
    ports = {s.port for s in svcs["10.0.0.5"]}
    assert ports == {22, 80}
