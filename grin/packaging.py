"""Pure builders for the desktop-app packaging: the macOS PyInstaller command and the Linux
.desktop file content. The shell scripts in scripts/ call these; keeping them pure makes the
build commands unit-testable."""


def pyinstaller_argv(entry: str = "grin/app/launch.py", name: str = "Grin",
                     icon: str = "assets/grin.icns") -> list:
    """The macOS `.app` build command (argv[0] == 'pyinstaller', on PATH after pip install).
    --windowed produces a .app; --collect-all grin bundles the package (incl. app/assets)."""
    return ["pyinstaller", "--noconfirm", "--windowed", "--name", name,
            "--icon", icon, "--collect-all", "grin", entry]


def desktop_file_content(exec_cmd: str = "grin app", icon: str = "grin") -> str:
    return (
        "[Desktop Entry]\n"
        "Name=Grin\n"
        "GenericName=Red-team orchestrator\n"
        "Comment=Autonomous red-team orchestrator\n"
        f"Exec={exec_cmd}\n"
        f"Icon={icon}\n"
        "Type=Application\n"
        "Terminal=false\n"
        "Categories=Security;Utility;\n"
    )
