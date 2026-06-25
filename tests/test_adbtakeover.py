from unittest import mock

from grin.tools import adbtakeover as t


def test_connect_builds_serial():
    with mock.patch.object(t, "_run") as r:
        assert t.connect("1.2.3.4", "5555") == "1.2.3.4:5555"
    r.assert_called_once()
    assert r.call_args.args[0] == ["adb", "connect", "1.2.3.4:5555"]


def test_fingerprint_parses_getprop_and_id(monkeypatch):
    outs = {
        ("getprop", "ro.product.manufacturer"): "samsung",
        ("getprop", "ro.product.model"): "SM-J700F",
        ("getprop", "ro.build.version.release"): "6.0.1",
        ("id",): "uid=2000(shell) gid=2000(shell) context=u:r:shell:s0",
    }

    def fake_run(argv, **kw):
        key = tuple(argv[4:])  # after: adb -s <serial> shell
        return mock.Mock(stdout=outs.get(key, ""), returncode=0)

    monkeypatch.setattr(t, "_run", fake_run)
    fp = t.fingerprint("1.2.3.4:5555")
    assert fp["ro.product.model"] == "SM-J700F"
    assert fp["ro.product.manufacturer"] == "samsung"
    assert "uid=2000(shell)" in fp["id"]


def test_user_apps_parses_package_list(monkeypatch):
    monkeypatch.setattr(t, "_run",
                        lambda argv, **k: mock.Mock(stdout="package:com.foo\npackage:com.bar\n", returncode=0))
    assert t.user_apps("s") == ["com.foo", "com.bar"]


def test_takeover_reports_shell_and_mirror(monkeypatch, tmp_path):
    monkeypatch.setattr(t, "connect", lambda *a: "1.2.3.4:5555")
    monkeypatch.setattr(t, "fingerprint",
                        lambda s: {"id": "uid=2000(shell)", "ro.product.model": "SM-J700F",
                                   "ro.product.manufacturer": "samsung", "ro.build.version.release": "6.0.1"})
    monkeypatch.setattr(t, "user_apps", lambda s: ["com.x"])
    monkeypatch.setattr(t, "screenshot", lambda s, o: o)
    monkeypatch.setattr(t, "launch_mirror", lambda s: "scrcpy launched — control on the desktop")

    res = t.takeover("1.2.3.4", mirror=True, screenshot_out=str(tmp_path / "x.png"))
    assert res["shell"] is True
    assert res["apps"] == ["com.x"]
    assert res["mirror"].startswith("scrcpy")

    out = t.render(res)
    assert "ADB TAKEOVER" in out and "SM-J700F" in out and "scrcpy" in out


def test_takeover_no_shell_is_honest(monkeypatch):
    monkeypatch.setattr(t, "connect", lambda *a: "s")
    monkeypatch.setattr(t, "fingerprint", lambda s: {"id": ""})  # no uid= -> no shell
    res = t.takeover("1.2.3.4")
    assert res["shell"] is False
    assert "could NOT get a shell" in t.render(res)


def test_mirror_warns_when_scrcpy_missing(monkeypatch):
    monkeypatch.setattr(t.shutil, "which", lambda x: None)
    assert "NOT installed" in t.launch_mirror("s")
