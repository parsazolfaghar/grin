from grin.runner import ExecResult, FakeRunner, LocalRunner, SSHRunner, build_runner


def test_fake_runner_returns_configured_result():
    r = FakeRunner({"id": ExecResult(output="uid=0(root)", exit_code=0,
                                     duration_s=0.0, timed_out=False)})
    res = r.run("t", "id")
    assert res.output == "uid=0(root)"
    assert res.exit_code == 0
    res2 = r.run("t", "whoami")
    assert "whoami" in res2.output
    assert res2.timed_out is False


def test_local_runner_executes_and_captures_exit_code():
    res = LocalRunner().run("localhost", "echo grin-ok")
    assert "grin-ok" in res.output
    assert res.exit_code == 0
    assert res.duration_s >= 0
    assert res.timed_out is False


def test_local_runner_nonzero_exit_code():
    res = LocalRunner().run("localhost", "exit 3")
    assert res.exit_code == 3


def test_local_runner_timeout_is_graceful():
    res = LocalRunner(default_timeout=1).run("x", "sleep 5")
    assert res.timed_out is True
    assert res.exit_code is None


def test_build_runner_local_and_ssh():
    assert isinstance(build_runner({"kind": "local"}), LocalRunner)
    assert isinstance(build_runner({"kind": "ssh", "ssh_host": "kali@10.0.0.50"}), SSHRunner)


def test_build_runner_unknown_kind_raises():
    import pytest
    with pytest.raises(ValueError):
        build_runner({"kind": "carrier-pigeon"})


def test_ssh_runner_builds_expected_argv(monkeypatch):
    captured = {}

    class _P:
        stdout, stderr, returncode = "remote-out", "", 0

    def fake_run(argv, **kw):
        captured["argv"] = argv
        return _P()

    monkeypatch.setattr("grin.runner.subprocess.run", fake_run)
    res = SSHRunner("kali@10.0.0.50").run("10.0.0.7", "nmap -sV 10.0.0.7")
    assert res.output == "remote-out"
    assert res.exit_code == 0
    assert captured["argv"][0] == "ssh" and "kali@10.0.0.50" in captured["argv"]
    assert "nmap -sV 10.0.0.7" in captured["argv"][-1]


def test_build_runner_auto_local_when_host_has_arsenal(monkeypatch):
    import grin.runner as r
    from grin.runner import LocalRunner
    monkeypatch.setattr("grin.platform_info.host_has_arsenal", lambda *a, **k: True)
    assert isinstance(r.build_runner({"kind": "auto"}), LocalRunner)


def test_build_runner_auto_arsenal_when_not(monkeypatch):
    import grin.runner as r
    from grin.runner import ArsenalRunner
    monkeypatch.setattr("grin.platform_info.host_has_arsenal", lambda *a, **k: False)
    assert isinstance(r.build_runner({"kind": "auto"}), ArsenalRunner)


def test_arsenal_ask_records_request(tmp_path):
    from grin.runner import ArsenalRunner
    from grin.toolrequest import ToolRequestStore
    store = ToolRequestStore(str(tmp_path / "t.json"))
    r = ArsenalRunner(client=None, acquire="ask", requests=store)
    res = r.run("t", "sqlmap -u http://t", timeout=5)
    assert res.exit_code == 127
    assert "approval" in res.output.lower()
    assert store.requested() == ["sqlmap"]


def test_arsenal_never_uses_add_message(tmp_path):
    from grin.runner import ArsenalRunner
    r = ArsenalRunner(client=None, acquire="never")
    res = r.run("t", "sqlmap -u http://t", timeout=5)
    assert res.exit_code == 127
    assert "grin arsenal add" in res.output


def test_arsenal_ask_without_store_falls_back(tmp_path):
    from grin.runner import ArsenalRunner
    r = ArsenalRunner(client=None, acquire="ask", requests=None)
    res = r.run("t", "sqlmap -u http://t", timeout=5)
    assert "grin arsenal add" in res.output


def test_arsenal_autoinstall_back_compat(tmp_path):
    from grin.runner import ArsenalRunner
    r = ArsenalRunner(client=None, autoinstall=True)
    assert r._acquire == "auto"
