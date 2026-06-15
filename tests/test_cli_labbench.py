from grin import cli
from grin.lab.answers import Target
from grin.labbench.matrix import Matrix


def test_labbench_dispatches_and_writes_report(tmp_path, monkeypatch, capsys):
    targets = [Target("t1-ssh", "grin-lab-ssh", "172.30.0.11", "easy", [22],
                      "weak-credentials", ["ssh weak credentials"], "GRIN{a}", "flag-in-loot")]
    monkeypatch.setattr(cli, "_lab_targets", lambda: targets)
    monkeypatch.setattr(cli, "_load_matrix",
                        lambda p: Matrix({"planner": "p", "recon": "r", "exploit": "e"},
                                         {"exploit": ["e"]}, 1))
    monkeypatch.setattr(cli, "_labbench_reset_fn", lambda *a, **k: (lambda: None))
    from grin.labbench.scorers import RunArtifact
    monkeypatch.setattr(cli, "_labbench_collect_fn",
                        lambda *a, **k: (lambda target, pins: RunArtifact(
                            target.id, f"got {target.flag}", "ssh weak credentials",
                            [], "ok", 1.0)))
    out = tmp_path / "report.txt"
    rc = cli.main(["labbench", "--matrix", "lab/matrix.yaml", "--out", str(out)])
    assert rc == 0
    text = out.read_text()
    assert "exploit" in text and "best" in text
