from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_compose_defines_internal_network_and_all_targets():
    data = yaml.safe_load((ROOT / "lab" / "docker-compose.yml").read_text())
    net = data["networks"]["grin-lab"]
    assert net["internal"] is True
    assert net["ipam"]["config"][0]["subnet"] == "172.30.0.0/24"
    svc = data["services"]
    assert set(svc) == {"t1-ssh", "t2-web", "t3-chain", "t4-crack", "t5-ssti",
                        "t6-pivot-web", "t6-pivot-vault"}
    ips = {name: s["networks"]["grin-lab"]["ipv4_address"] for name, s in svc.items()}
    assert ips == {"t1-ssh": "172.30.0.11", "t2-web": "172.30.0.12", "t3-chain": "172.30.0.13",
                   "t4-crack": "172.30.0.14", "t5-ssti": "172.30.0.15",
                   "t6-pivot-web": "172.30.0.16", "t6-pivot-vault": "172.30.0.17"}
    assert svc["t1-ssh"]["container_name"] == "grin-lab-ssh"
    assert svc["t6-pivot-vault"]["container_name"] == "grin-lab-pivot-vault"


def test_dockerfiles_exist():
    for f in ("Dockerfile.t1-ssh", "Dockerfile.t2-web", "Dockerfile.t3-chain",
              "Dockerfile.t4-crack", "Dockerfile.t5-ssti",
              "Dockerfile.t6-pivot-web", "Dockerfile.t6-pivot-vault"):
        assert (ROOT / "lab" / f).exists(), f
