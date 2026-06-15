"""Benchmark matrix: candidate models per role + the one-role-at-a-time run plan."""
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass
class Matrix:
    default_pins: dict
    candidates: dict
    repeats: int


@dataclass
class RunSpec:
    role: str
    model: str
    pins: dict
    target_id: str
    repeat: int


def load_matrix(path: str) -> Matrix:
    data = yaml.safe_load(Path(path).read_text()) or {}
    return Matrix(
        default_pins=dict(data.get("default_pins") or {}),
        candidates=dict(data.get("candidates") or {}),
        repeats=int(data.get("repeats", 1)),
    )


def plan_runs(matrix: Matrix, target_ids: list) -> list:
    runs = []
    for role, models in matrix.candidates.items():
        for model in models:
            for tid in target_ids:
                for rep in range(max(1, matrix.repeats)):
                    pins = dict(matrix.default_pins)
                    pins[role] = model
                    runs.append(RunSpec(role=role, model=model, pins=pins,
                                        target_id=tid, repeat=rep))
    return runs
