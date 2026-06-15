from grin import cli


def test_lab_status_dispatches(monkeypatch, capsys):
    called = {}

    def _fake_status(**k):
        called["status"] = k
        return 0

    monkeypatch.setattr(cli, "run_status", _fake_status)
    rc = cli.main(["lab", "status"])
    assert rc == 0 and "status" in called


def test_lab_reset_dispatches(monkeypatch):
    monkeypatch.setattr(cli, "run_reset", lambda: 0)
    assert cli.main(["lab", "reset"]) == 0


def test_lab_writes_engagement_yamls(tmp_path, monkeypatch):
    # `grin lab engagements <dir>` writes one YAML per target from the answer key.
    from grin.lab.answers import Target
    fake = [Target("t1-ssh", "grin-lab-ssh", "172.30.0.11", "easy", [22],
                   "weak-credentials", ["ssh weak credentials"], "GRIN{a}", "flag-in-loot")]
    monkeypatch.setattr(cli, "_lab_targets", lambda: fake)
    rc = cli.main(["lab", "engagements", str(tmp_path)])
    assert rc == 0
    out = tmp_path / "lab-t1-ssh.yaml"
    assert out.exists()
    import yaml
    d = yaml.safe_load(out.read_text())
    assert d["scope"]["in"] == ["172.30.0.11"]
