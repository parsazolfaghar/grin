"""Aggregate per-run scores into per-(role,model) rankings + a prose report (no tables)."""
from dataclasses import dataclass, field
from statistics import mean, median


@dataclass
class ModelAgg:
    role: str
    model: str
    flag_rate: float
    mean_recall: float
    total_refusals: int
    total_invalid: int
    median_time: float
    n_runs: int = 0
    runs: list = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return self.total_refusals == 0


def aggregate(rows: list) -> list:
    """rows: list of (role, model, RunScore). Returns ranked ModelAgg list (best first per role)."""
    groups = {}
    for role, model, score in rows:
        groups.setdefault((role, model), []).append(score)
    aggs = []
    for (role, model), scores in groups.items():
        aggs.append(ModelAgg(
            role=role, model=model,
            flag_rate=round(mean(1.0 if s.flag_captured else 0.0 for s in scores), 3),
            mean_recall=round(mean(s.findings_recall for s in scores), 3),
            total_refusals=sum(s.refusals for s in scores),
            total_invalid=sum(s.invalid_calls for s in scores),
            median_time=round(median(s.duration_s for s in scores), 2),
            n_runs=len(scores), runs=scores))
    aggs.sort(key=lambda a: (a.clean, a.flag_rate, a.mean_recall, -a.median_time), reverse=True)
    return aggs


def to_text(aggs: list) -> str:
    roles = []
    for a in aggs:
        if a.role not in roles:
            roles.append(a.role)
    lines = ["GRIN LIVE-BENCH — per-role ranking (flag-lab)", ""]
    for role in roles:
        ranked = [a for a in aggs if a.role == role]
        winner = ranked[0]
        lines.append(f"[{role}] best: {winner.model}  "
                     f"(flags {winner.flag_rate:.0%}, recall {winner.mean_recall:.0%}, "
                     f"{winner.median_time:.0f}s median)")
        for a in ranked:
            flag = "" if a.clean else "  REFUSED(x{})".format(a.total_refusals)
            lines.append(f"  - {a.model}: flags {a.flag_rate:.0%}, recall {a.mean_recall:.0%}, "
                         f"invalid {a.total_invalid}, {a.median_time:.0f}s, n={a.n_runs}{flag}")
        lines.append("")
    return "\n".join(lines)
