"""Generate Grin engagement definitions from answer-key targets, so engagement scope/IPs
never drift from the running lab. Returns plain dicts (YAML-serialisable)."""
from grin.lab.answers import Target


def engagement_dict(target: Target, *, runner_container: str = "grin-kali") -> dict:
    eid = f"lab-{target.id}"
    return {
        "id": eid,
        "name": f"Flag-lab {target.id} ({target.tier})",
        "mode": "own-lab",
        "scope": {"in": [target.ip], "exclude": []},
        "roe": {"allowed_actions": ["passive", "active-scan", "exploit", "post-exploit"],
                "windows": []},
        "autonomy": "autonomous",
        "env": {"kind": "docker", "container": runner_container},
        "audit_log": f"./audit/{eid}.jsonl",
        "state": "active",
    }
