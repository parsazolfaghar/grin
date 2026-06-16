"""Pure builder for the self-contained Setup bundle's PyInstaller command. Bundles the pre-built Grin
artifact as data so the installer carries Grin inside it. Per-OS data separator: ':' POSIX, ';' Win."""
import os


def setup_pyinstaller_argv(entry: str = "grin/setup/launch.py", name: str = "Grin Setup",
                           icon: str = "grin/app/assets/grin.icns",
                           grin_artifact: str = "dist/Grin.app", sep: str | None = None) -> list:
    sep = sep if sep is not None else (";" if os.name == "nt" else ":")
    return ["pyinstaller", "--noconfirm", "--windowed", "--name", name, "--icon", icon,
            "--add-data", f"{grin_artifact}{sep}grin_payload",
            "--collect-all", "grin", entry]
