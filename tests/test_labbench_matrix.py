from grin.labbench.matrix import load_matrix, plan_runs, Matrix


def _write(tmp_path):
    p = tmp_path / "matrix.yaml"
    p.write_text("""
default_pins: {planner: hermes3:8b, recon: qwen2.5-coder:7b, exploit: qwen3:14b}
candidates:
  exploit: [qwen3:14b, dolphin3:8b]
repeats: 2
""")
    return str(p)


def test_load_matrix(tmp_path):
    m = load_matrix(_write(tmp_path))
    assert isinstance(m, Matrix)
    assert m.default_pins["planner"] == "hermes3:8b"
    assert m.candidates["exploit"] == ["qwen3:14b", "dolphin3:8b"]
    assert m.repeats == 2


def test_plan_runs_sweeps_one_role_holding_others(tmp_path):
    m = load_matrix(_write(tmp_path))
    runs = plan_runs(m, ["t1-ssh", "t2-web"])
    assert len(runs) == 8
    r = runs[0]
    assert r.role == "exploit"
    assert r.pins["planner"] == "hermes3:8b" and r.pins["recon"] == "qwen2.5-coder:7b"
    models_used = {run.pins["exploit"] for run in runs}
    assert models_used == {"qwen3:14b", "dolphin3:8b"}


def test_plan_runs_pins_are_independent_copies(tmp_path):
    m = load_matrix(_write(tmp_path))
    runs = plan_runs(m, ["t1-ssh"])
    runs[0].pins["exploit"] = "MUTATED"
    assert runs[1].pins["exploit"] != "MUTATED"
