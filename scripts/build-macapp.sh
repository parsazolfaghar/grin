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

# 2. build deps + PyInstaller (argv[0] == "pyinstaller", on PATH after install)
python3 -m pip install --quiet pyinstaller pyqt6 docker pyyaml httpx
ARGS=$(python3 -c "from grin.packaging import pyinstaller_argv; print(' '.join(pyinstaller_argv(icon='grin/app/assets/grin.icns')))")
# shellcheck disable=SC2086
$ARGS --collect-all PyQt6

echo "built dist/Grin.app — drag to /Applications. First launch: right-click -> Open."
