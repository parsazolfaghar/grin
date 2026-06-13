"""An Objective — one unit of work the Orchestrator hands to an Executor: a plain-language
goal plus the target it runs against (a host, URL, or in-scope CIDR)."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Objective:
    objective: str
    target: str
