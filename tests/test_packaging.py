from grin.packaging import pyinstaller_argv, desktop_file_content


def test_pyinstaller_argv():
    argv = pyinstaller_argv(entry="grin/app/launch.py", name="Grin", icon="assets/grin.icns")
    assert argv[0] == "pyinstaller"
    assert "--windowed" in argv
    assert "--name" in argv and "Grin" in argv
    assert "--icon" in argv and "assets/grin.icns" in argv
    assert argv[-1] == "grin/app/launch.py"
    assert "--collect-all" in argv and "grin" in argv
    # the docker SDK is imported lazily -> must be collected so the bundled app can drive Docker
    assert "docker" in argv


def test_desktop_file_content():
    txt = desktop_file_content(exec_cmd="grin app", icon="grin")
    assert txt.startswith("[Desktop Entry]")
    assert "Name=Grin" in txt
    assert "Exec=grin app" in txt
    assert "Icon=grin" in txt
    assert "Type=Application" in txt
    assert "Terminal=false" in txt
