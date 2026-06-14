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
    refused_count: int = 0  # how many of the role's cases refused
    n_cases: int = 0        # total cases in this role


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


def run_bench(client, models, roles, cases, repeats: int = 3,
              temperature: float = 0.0) -> BenchReport:
    """Score every model x case. Generation is deterministic (temperature 0) and each case is
    sampled `repeats` times: the case score is the MEAN across samples and latency the MEDIAN,
    so close calls aren't decided by single-shot sampling/scheduling noise. A refusal in ANY
    sample flags the case."""
    from statistics import median
    sel = [c for c in cases if c.role in roles]
    case_results = []
    for model in models:
        for case in sel:
            system, user = case.build()
            scores, lats, refusals, last_bd, err = [], [], [], None, ""
            for _ in range(max(1, repeats)):
                t0 = time.monotonic()
                try:
                    raw = client.generate(model=model, system=system, prompt=user,
                                          temperature=temperature)
                except Exception as e:  # noqa: BLE001 - a dead model scores 0, run continues
                    raw, err = "", str(e)
                dt = time.monotonic() - t0
                bd = score_case(case, raw, dt)
                scores.append(0.0 if err else bd["score"])
                lats.append(dt)
                refusals.append(bd["refused"])
                last_bd = bd
                if err:
                    break
            case_results.append(CaseResult(
                model=model, case_name=case.name, role=case.role,
                score=round(mean(scores), 1), refused=any(refusals),
                latency_s=round(median(lats), 2), breakdown=last_bd, error=err))
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
                latency_s=round(mean(c.latency_s for c in cs), 2), cases=cs,
                refused_count=sum(1 for c in cs if c.refused), n_cases=len(cs)))
    return BenchReport(models=models, roles=roles, case_results=case_results,
                       role_results=role_results)
