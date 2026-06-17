"""Answer-key (ground truth) for the flag-lab. One Target per vulnerable container."""
from dataclasses import dataclass, field
from pathlib import Path

import yaml


class AnswerKeyError(Exception):
    pass


@dataclass(frozen=True)
class Target:
    id: str
    container: str
    ip: str
    tier: str
    open_ports: list
    vuln_class: str
    expected_findings: list
    flag: str
    win: str
    extra_scope: list = field(default_factory=list)   # extra in-scope hosts (e.g. T6 pivot vault)


_REQUIRED = ("id", "container", "ip", "tier", "open_ports", "vuln_class",
             "expected_findings", "flag", "win")


def load_answers(path: str) -> list:
    try:
        data = yaml.safe_load(Path(path).read_text()) or {}
    except (OSError, yaml.YAMLError) as e:
        raise AnswerKeyError(f"cannot read answer key {path}: {e}") from e
    rows = data.get("targets") or []
    if not rows:
        raise AnswerKeyError(f"answer key {path} has no targets")
    targets = []
    for i, row in enumerate(rows):
        missing = [k for k in _REQUIRED if k not in row]
        if missing:
            raise AnswerKeyError(f"target #{i} missing fields: {missing}")
        targets.append(Target(
            id=row["id"], container=row["container"], ip=row["ip"], tier=row["tier"],
            open_ports=list(row["open_ports"]), vuln_class=row["vuln_class"],
            expected_findings=list(row["expected_findings"]), flag=row["flag"], win=row["win"],
            extra_scope=list(row.get("extra_scope", []))))
    return targets


def by_id(targets: list, target_id: str):
    for t in targets:
        if t.id == target_id:
            return t
    return None
