#!/usr/bin/env bash
# Build a clickable macOS Grin.app (unsigned). Run on macOS. Output: dist/Grin.app
# First launch: right-click -> Open (unsigned / Gatekeeper "unidentified developer").
# Real signing/notarization needs an Apple Developer cert ($99/yr) — out of scope.
set -euo pipefail
cd "$(dirname "$0")/.."

# 1. icon: grin/app/assets/icon.png -> grin/app/assets/grin.icns
SRC=grin/app/assets/icon.png
ICNS=grin/app/assets/grin.icns
if [ ! -f "$ICNS" ]; then
  ICONSET="$(mktemp -d)/grin.iconset"; mkdir -p "$ICONSET"
  for s in 16 32 128 256 512; do
    sips -z "$s" "$s" "$SRC" --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
    sips -z "$((s * 2))" "$((s * 2))" "$SRC" --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
  done
  iconutil -c icns "$ICONSET" -o "$ICNS"
fi

# 2. isolated build venv (PEP 668: don't touch the system/Homebrew Python). Install grin (so
#    PyInstaller can analyze the package) + the GUI + build deps into it.
# Prefer python3.12: PyInstaller's macOS windowed bootloader is flaky on bleeding-edge 3.14.
PYBUILD="${GRIN_BUILD_PYTHON:-$(command -v python3.12 || command -v python3)}"
echo "build python: $("$PYBUILD" --version)"
VENV=.build-venv
rm -rf "$VENV"
"$PYBUILD" -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -e . pyinstaller pyqt6 docker
# argv[0] == "pyinstaller"; run the venv's pyinstaller (on PATH via the venv bin)
ARGS=$("$VENV/bin/python" -c "from grin.packaging import pyinstaller_argv; print(' '.join(pyinstaller_argv(icon='grin/app/assets/grin.icns')))")
# shellcheck disable=SC2086
PATH="$PWD/$VENV/bin:$PATH" $ARGS --collect-all PyQt6

echo "built dist/Grin.app — drag to /Applications. First launch: right-click -> Open."
