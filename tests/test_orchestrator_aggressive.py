from pathlib import Path
from datetime import datetime
from grin.catalog import load_catalog
from grin.orchestrator import orchestrate
from grin.engagement import validate_engagement

CAT = str(Path(__file__).resolve().parents[1] / "catalog" / "attack_catalog.yaml")


def _eng(tmp_path):
    return validate_engagement({
        "id": "e", "name": "n", "mode": "own-lab",
        "scope": {"in": ["10.0.0.5"], "exclude": []},
        "roe": {"allowed_actions": ["passive", "active-scan", "exploit", "post-exploit"], "windows": []},
        "autonomy": "autonomous", "env": {"kind": "local"},
        "audit_log": str(tmp_path / "a.jsonl"), "state": "active"})


class _UpClient:
    def is_up(self):
        return True
    def generate(self, **k):
        return "{}"   # planner returns empty plan; aggressive sweep provides objectives


def _fake_execute_factory(ran, tmp_path):
    def fake_execute_task(eng, *, objective, target, client, runner, now, model,
                          max_steps, engagement_path):
        ran.append(objective)
        from grin.executor import TaskResult
        from grin.journal import Journal
        j = Journal(task_id="t", objective=objective, target=target,
                    engagement_path="", path=str(tmp_path / f"{len(ran)}.json"))
        return TaskResult("completed", [], j, secrets=[])
    return fake_execute_task


def test_aggressive_runs_catalog_objectives(tmp_path, monkeypatch):
    import grin.orchestrator as orch
    cat = load_catalog(CAT)
    ran = []
    monkeypatch.setattr(orch, "execute_task", _fake_execute_factory(ran, tmp_path))
    orchestrate(_eng(tmp_path), goal="own the box",
                planner_client=_UpClient(), executor_client=_UpClient(),
                runner=object(), now=datetime(2026, 1, 1), model="m",
                aggressive=True, catalog=cat, max_objectives=24, max_steps=80)
    assert any(o.startswith("[T1595") for o in ran)


def test_non_aggressive_unchanged(tmp_path, monkeypatch):
    import grin.orchestrator as orch
    ran = []
    monkeypatch.setattr(orch, "execute_task", _fake_execute_factory(ran, tmp_path))
    orchestrate(_eng(tmp_path), goal="g", planner_client=_UpClient(),
                executor_client=_UpClient(), runner=object(), now=datetime(2026, 1, 1), model="m")
    assert not any(o.startswith("[T1595") for o in ran)
