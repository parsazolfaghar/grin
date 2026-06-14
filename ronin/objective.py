"""An Objective — one unit of work the Orchestrator hands to an Executor: a plain-language
goal plus the target it runs against (a host, URL, or in-scope CIDR). The action_class is an
advisory hint for model routing only; the spine still authorizes each actual command."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Objective:
    objective: str
    target: str
    action_class: str = ""
