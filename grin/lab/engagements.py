"""Generate Grin engagement definitions from answer-key targets, so engagement scope/IPs
never drift from the running lab. Returns plain dicts (YAML-serialisable)."""
from grin.lab.answers import Target


def engagement_dict(target: Target, *, runner_container: str = "grin-kali",
                    env_kind: str = "docker") -> dict:
    eid = f"lab-{target.id}"
    # "docker" pins one runner container; "arsenal" routes tools across the whole self-provisioned
    # arsenal (grin-kali + grin-blackarch) via ArsenalRunner — so a run exercises BOTH distros and
    # auto-installs a missing tool (frictionless-within-authorization).
    if env_kind == "arsenal":
        env = {"kind": "arsenal", "tool_acquire": "auto"}
    else:
        env = {"kind": "docker", "container": runner_container}
    return {
        "id": eid,
        "name": f"Flag-lab {target.id} ({target.tier})",
        "mode": "own-lab",
        # extra_scope authorises pivot/lateral targets (e.g. T6's vault host) beyond the entry IP.
        "scope": {"in": [target.ip, *target.extra_scope], "exclude": []},
        "roe": {"allowed_actions": ["passive", "active-scan", "exploit", "post-exploit"],
                "windows": []},
        "autonomy": "autonomous",
        "env": env,
        "audit_log": f"./audit/{eid}.jsonl",
        "state": "active",
    }
