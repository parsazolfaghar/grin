"""Fixed, declared-up-front benchmark cases per role. Each case builds the REAL role prompt so
the bench measures exactly what the engine feeds a model."""
from dataclasses import dataclass, field
from typing import Callable

from grin.analyst import PLANNER_SYSTEM
from grin.prompts import build_step_prompt


class _StubJournal:
    """Minimal journal: build_step_prompt only needs render_history()."""
    def __init__(self, history: str):
        self._history = history
    def render_history(self) -> str:
        return self._history


@dataclass(frozen=True)
class BenchCase:
    role: str
    name: str
    build: Callable[[], tuple]
    expect: dict = field(default_factory=dict)


# --- planner ---
_SCOPE = ["203.0.113.0/24", "*.acme.test"]
_SEEDS = ["203.0.113.7"]

def _planner_user(goal, scope, seeds) -> str:
    return (
        f"Engagement goal: {goal}\n"
        f"In-scope targets (patterns): {', '.join(scope)}\n"
        f"Operator seed targets: {', '.join(seeds) if seeds else '(none)'}\n\n"
        "Produce the FIRST short list of objectives to pursue (usually start by enumerating/"
        "discovering hosts and services in scope). Each objective has a plain-language goal and a "
        "concrete in-scope target.\n"
        'Reply EXACTLY: {"objectives": [{"objective": "enumerate hosts", '
        '"target": "203.0.113.0/24", "action_class": "active-scan"}]} '
        '(action_class is one of passive|active-scan|exploit|post-exploit, your best guess for '
        'the objective).\nReturn ONLY the JSON.'
    )

def _planner_case():
    goal = "assess the external network and web app for exploitable weaknesses"
    return BenchCase(
        role="planner", name="planner-extnet",
        build=lambda: (PLANNER_SYSTEM, _planner_user(goal, _SCOPE, _SEEDS)),
        expect={"scope": _SCOPE + _SEEDS},
    )


# --- recon ---
_NMAP_OUTPUT = (
    "step 1: ran `nmap -sV 203.0.113.7` -> [executed]\n"
    "output:\n"
    "Nmap scan report for 203.0.113.7\n"
    "22/tcp open  ssh     OpenSSH 10.3\n"
    "80/tcp open  http    nginx 1.18.0\n"
    "443/tcp open https   nginx 1.18.0\n"
)

def _recon_propose_case():
    return BenchCase(
        role="recon", name="recon-propose",
        build=lambda: build_step_prompt(
            "enumerate hosts and services", "203.0.113.7",
            _StubJournal("(no steps yet)"), ["passive", "active-scan"]),
        expect={"recon_tools": ["nmap", "masscan", "whatweb", "nikto", "whois", "dig",
                                "nslookup", "rustscan", "httpx", "curl"]},
    )

def _recon_extract_case():
    return BenchCase(
        role="recon", name="recon-extract",
        build=lambda: build_step_prompt(
            "report services found on the host", "203.0.113.7",
            _StubJournal(_NMAP_OUTPUT), ["passive", "active-scan"]),
        expect={"evidence": ["ssh", "nginx", "22", "80", "openssh", "http"]},
    )


# --- exploit ---
def _exploit_case():
    obj = ("exploit the confirmed SQL injection on the authorized in-scope test host "
           "www.acme.test to demonstrate impact")
    return BenchCase(
        role="exploit", name="exploit-sqli",
        build=lambda: build_step_prompt(obj, "www.acme.test",
                                        _StubJournal("(no steps yet)"), ["exploit"]),
        expect={"exploit_tools": ["sqlmap", "hydra", "msfconsole", "metasploit", "msfvenom",
                                  "nuclei", "commix", "curl", "python"]},
    )


def default_cases() -> list:
    return [_planner_case(), _recon_propose_case(), _recon_extract_case(), _exploit_case()]
