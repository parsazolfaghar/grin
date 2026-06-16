#!/usr/bin/env bash
# Build the self-contained macOS Grin Setup.app (unsigned). Builds Grin.app first, then bundles it
# inside Grin Setup.app. First launch: right-click -> Open.
set -euo pipefail
cd "$(dirname "$0")/.."

# 1. build the main Grin.app (produces dist/Grin.app + the icns) in the isolated .build-venv
bash scripts/build-macapp.sh

# 2. build the Setup bundle in the same venv, bundling dist/Grin.app as the payload.
#    Invoke PyInstaller via its Python API with the argv LIST so the space in "Grin Setup" survives
#    (an unquoted shell expansion would split it and break the build).
VENV=.build-venv   # created by build-macapp.sh
"$VENV/bin/python" - <<'PY'
import PyInstaller.__main__ as m
from grin.setup.packaging import setup_pyinstaller_argv
args = setup_pyinstaller_argv(icon="grin/app/assets/grin.icns", grin_artifact="dist/Grin.app")[1:]
args += ["--collect-all", "PyQt6"]
m.run(args)
PY
echo "built 'dist/Grin Setup.app' — share it; first launch: right-click -> Open."
