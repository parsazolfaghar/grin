"""Action-class taxonomy + anti-spoof class resolution.

The spine — not the caller — sets the effective action class. A caller (later, an
agent) proposes a class, but resolve_class() cross-checks the tool against a
minimum-class catalog and takes the HIGHER of (declared, catalog floor). An unknown
tool floors to active-scan, so an unknown command can never auto-pass as passive.
"""
import os

# Increasing intrusiveness. Index = rank.
ACTION_CLASSES = ("passive", "active-scan", "exploit", "post-exploit")
_RANK = {c: i for i, c in enumerate(ACTION_CLASSES)}

# Conservative floor for any tool not in the catalog.
UNKNOWN_FLOOR = "active-scan"

# Minimum class per well-known tool. Small in SP1; grows with SP2 (the Executor
# knows the arsenal). Keys are bare tool names, lowercased.
TOOL_CATALOG = {
    # passive — no packets to the target
    "whois": "passive", "dig": "passive", "host": "passive", "nslookup": "passive",
    "theharvester": "passive", "sublist3r": "passive", "amass": "passive",
    # active-scan — non-exploitative probing
    "nmap": "active-scan", "masscan": "active-scan", "nuclei": "active-scan",
    "dirb": "active-scan", "gobuster": "active-scan", "feroxbuster": "active-scan",
    "whatweb": "active-scan", "nikto": "active-scan", "wpscan": "active-scan",
    # exploit — attempts access / triggers a vuln
    "sqlmap": "exploit", "hydra": "exploit", "medusa": "exploit",
    "metasploit": "exploit", "msfconsole": "exploit", "msfvenom": "exploit",
    "commix": "exploit", "crackmapexec": "exploit",
    # post-exploit — actions on a compromised host
    "mimikatz": "post-exploit", "bloodhound": "post-exploit",
    "meterpreter": "post-exploit",
}


def class_rank(action_class: str) -> int:
    """Rank of a class; -1 for anything not a valid class (so it can never win a max())."""
    return _RANK.get(action_class, -1)


def _tool_floor(tool: str) -> str:
    name = os.path.basename((tool or "").strip()).lower()
    return TOOL_CATALOG.get(name, UNKNOWN_FLOOR)


def resolve_class(tool: str, declared: str | None) -> str:
    """The effective class = max rank of (declared, catalog floor). Fail-closed: an
    invalid/missing declared class contributes rank -1, so the floor always wins."""
    floor = _tool_floor(tool)
    if class_rank(declared) > class_rank(floor):
        return declared
    return floor
