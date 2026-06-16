from grin.setup.packaging import setup_pyinstaller_argv


def test_setup_argv_bundles_grin_and_is_windowed():
    argv = setup_pyinstaller_argv(entry="grin/setup/launch.py", name="Grin Setup",
                                  icon="grin/app/assets/grin.icns", grin_artifact="dist/Grin.app")
    assert argv[0] == "pyinstaller"
    assert "--windowed" in argv
    assert "--name" in argv and "Grin Setup" in argv
    assert argv[-1] == "grin/setup/launch.py"
    joined = " ".join(argv)
    assert "--add-data" in argv and "dist/Grin.app" in joined
    assert "--collect-all" in argv and "grin" in argv
