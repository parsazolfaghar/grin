"""Attack-strength presets: map a named level to the engine's aggression/budget knobs. Pure; unknown
levels fall back to 'normal'. Strength never widens authorization — it only sets the aggressive flag,
objective/step budgets, and (via the ad-hoc builder) the recon action cap."""
from dataclasses import dataclass

STRENGTH_LEVELS = ("recon", "normal", "aggressive", "max")


@dataclass(frozen=True)
class StrengthParams:
    aggressive: bool
    max_objectives: int
    max_steps: int
    recon_only: bool


_TABLE = {
    "recon": StrengthParams(aggressive=False, max_objectives=5, max_steps=8, recon_only=True),
    "normal": StrengthParams(aggressive=False, max_objectives=10, max_steps=12, recon_only=False),
    "aggressive": StrengthParams(aggressive=True, max_objectives=24, max_steps=12, recon_only=False),
    "max": StrengthParams(aggressive=True, max_objectives=40, max_steps=20, recon_only=False),
}


def strength_params(level: str) -> StrengthParams:
    return _TABLE.get(level, _TABLE["normal"])
