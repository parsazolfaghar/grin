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
def _exploit_cases() -> list:
    """A spread of authorized, prerequisite-met offensive scenarios. `right` = the correct toolset
    for THAT vuln (the scorer also credits any offensive tool partially). Each history states the
    prerequisite is satisfied so the model should act, not re-recon."""
    sqli = ("exploit the CONFIRMED SQL injection in the `id` parameter on the authorized in-scope "
            "host www.acme.test to demonstrate impact (extract data)")
    creds = ("the in-scope host 203.0.113.12 exposes SSH on 22 with a weak/guessable password; you "
             "are authorized to perform an online credential attack to gain access")
    cve = ("the in-scope host 203.0.113.7 runs vsftpd 2.3.4 (a service with a well-known public "
           "exploit); you are authorized to exploit it to get a shell")
    rce = ("the web app on www.acme.test has a CONFIRMED OS command-injection in the `ping` form "
           "field; you are authorized to exploit it for remote code execution")
    post = ("you already hold a low-privilege shell on the in-scope Linux host 203.0.113.7; "
            "escalate to root")
    return [
        BenchCase(role="exploit", name="exploit-sqli",
                  build=lambda: build_step_prompt(sqli, "www.acme.test",
                                                  _StubJournal("(SQLi already confirmed)"), ["exploit"]),
                  expect={"right": ["sqlmap", "commix"]}),
        BenchCase(role="exploit", name="exploit-weak-creds",
                  build=lambda: build_step_prompt(creds, "203.0.113.12",
                                                  _StubJournal("(ssh 22 open, weak creds)"), ["exploit"]),
                  expect={"right": ["hydra", "medusa", "ncrack", "patator"]}),
        BenchCase(role="exploit", name="exploit-known-cve",
                  build=lambda: build_step_prompt(cve, "203.0.113.7",
                                                  _StubJournal("(vsftpd 2.3.4 fingerprinted)"), ["exploit"]),
                  expect={"right": ["msfconsole", "metasploit", "msf", "searchsploit", "nuclei"]}),
        BenchCase(role="exploit", name="exploit-web-rce",
                  build=lambda: build_step_prompt(rce, "www.acme.test",
                                                  _StubJournal("(command injection confirmed)"), ["exploit"]),
                  expect={"right": ["commix", "msfvenom", "weevely", "curl"]}),
        BenchCase(role="exploit", name="exploit-postexploit",
                  build=lambda: build_step_prompt(post, "203.0.113.7",
                                                  _StubJournal("you have a low-priv shell on 203.0.113.7"),
                                                  ["exploit", "post-exploit"]),
                  expect={"right": ["linpeas", "gtfobins", "msfconsole", "sudo", "getsystem",
                                    "linenum", "pspy"]}),
    ]


def default_cases() -> list:
    return [_planner_case(), _recon_propose_case(), _recon_extract_case(), *_exploit_cases()]
