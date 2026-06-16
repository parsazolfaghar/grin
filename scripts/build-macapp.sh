#!/usr/bin/env bash
# Build a clickable macOS Grin.app (unsigned). Run on macOS. Output: dist/Grin.app
# First launch: right-click -> Open (unsigned / Gatekeeper "unidentified developer").
# Real signing/notarization needs an Apple Developer cert ($99/yr) — out of scope.
set -euo pipefail
cd "$(dirname "$0")/.."

# 1. icon: assets/icon.png -> assets/grin.icns
if [ ! -f assets/grin.icns ]; then
  ICONSET="$(mktemp -d)/grin.iconset"; mkdir -p "$ICONSET"
  for s in 16 32 128 256 512; do
    sips -z "$s" "$s" assets/icon.png --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
    sips -z "$((s * 2))" "$((s * 2))" assets/icon.png --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
  done
  iconutil -c icns "$ICONSET" -o assets/grin.icns
fi

# 2. build deps + PyInstaller (argv[0] == "pyinstaller", on PATH after install)
python3 -m pip install --quiet pyinstaller pyqt6 docker pyyaml httpx
ARGS=$(python3 -c "from grin.packaging import pyinstaller_argv; print(' '.join(pyinstaller_argv(icon='assets/grin.icns')))")
# shellcheck disable=SC2086
$ARGS --collect-all PyQt6

echo "built dist/Grin.app — drag to /Applications. First launch: right-click -> Open."
