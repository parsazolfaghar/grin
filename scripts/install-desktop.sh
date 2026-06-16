#!/usr/bin/env bash
# Install the Grin launcher entry + icon on Linux (non-NixOS). On NixOS/user it's declarative
# (Grin is already in the launcher). Needs `grin` on PATH (e.g. `pip install -e .`).
set -euo pipefail
cd "$(dirname "$0")/.."
APPS="$HOME/.local/share/applications"
ICONS="$HOME/.local/share/icons/hicolor/256x256/apps"
mkdir -p "$APPS" "$ICONS"
python3 -c "from grin.packaging import desktop_file_content; print(desktop_file_content(), end='')" \
  > "$APPS/grin.desktop"
cp grin/app/assets/icon.png "$ICONS/grin.png"
update-desktop-database "$APPS" 2>/dev/null || true
echo "installed grin.desktop -> appears in your app launcher (Exec=grin app; needs grin on PATH)"
