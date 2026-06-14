"""Run the battery: model x case -> timed generate -> score -> aggregate ranked RoleResults."""
import time
from dataclasses import dataclass, field
from statistics import mean

from grin.bench.scorers import score_case


@dataclass
class CaseResult:
    model: str
    case_name: str
    role: str
    score: float
    refused: bool
    latency_s: float
    breakdown: dict
    error: str = ""


@dataclass
class RoleResult:
    model: str
    role: str
    score: float           # mean of the role's case scores
    refused: bool          # any case refused
    latency_s: float       # mean latency
    cases: list = field(default_factory=list)


@dataclass
class BenchReport:
    models: list
    roles: list
    case_results: list
    role_results: list

    def role_result(self, model, role):
        for r in self.role_results:
            if r.model == model and r.role == role:
                return r
        return None

    def ranking(self, role):
        rows = [(r.model, r.score) for r in self.role_results if r.role == role]
        return sorted(rows, key=lambda x: x[1], reverse=True)

    def recommended_pins(self) -> dict:
        pins = {}
        for role in self.roles:
            ranked = [r for r in self.role_results if r.role == role]
            if not ranked:
                continue
            ranked.sort(key=lambda r: (r.score, -r.latency_s), reverse=True)
            pins[role] = ranked[0].model
        return pins


def run_bench(client, models, roles, cases) -> BenchReport:
    sel = [c for c in cases if c.role in roles]
    case_results = []
    for model in models:
        for case in sel:
            system, user = case.build()
            t0 = time.monotonic()
            err = ""
            try:
                raw = client.generate(model=model, system=system, prompt=user, temperature=0.2)
            except Exception as e:  # noqa: BLE001 - a dead model scores 0, run continues
                raw, err = "", str(e)
            dt = time.monotonic() - t0
            bd = score_case(case, raw, dt)
            case_results.append(CaseResult(
                model=model, case_name=case.name, role=case.role,
                score=0.0 if err else bd["score"], refused=bd["refused"],
                latency_s=round(dt, 2), breakdown=bd, error=err))
    role_results = []
    for model in models:
        for role in roles:
            cs = [c for c in case_results if c.model == model and c.role == role]
            if not cs:
                continue
            role_results.append(RoleResult(
                model=model, role=role,
                score=round(mean(c.score for c in cs), 1),
                refused=any(c.refused for c in cs),
                latency_s=round(mean(c.latency_s for c in cs), 2), cases=cs))
    return BenchReport(models=models, roles=roles, case_results=case_results,
                       role_results=role_results)
