#!/usr/bin/env bash
# install-on-kali.sh — install Grin on Kali/Debian as a clickable, cloud-backed app.
# Idempotent: safe to re-run (that's also what update.sh calls).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
REPO="$(dirname "$SCRIPT_DIR")"
cd "$REPO"
say() { printf '\n\033[1;32m== %s\033[0m\n' "$1"; }

say "System dependencies (sudo apt)"
sudo apt-get update -y
# python + pipx, git, and the Qt runtime libs PyQt6's wheels need on a headless-ish base.
sudo apt-get install -y python3 python3-venv python3-pip pipx git \
  libgl1 libegl1 libxkbcommon0 libxcb-cursor0 libxcb-xinerama0 libxcb-icccm4 \
  libxcb-image0 libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxcb-shape0 \
  libdbus-1-3 fontconfig

say "Installing Grin via pipx (editable, with GUI + docker support)"
pipx install --force -e ".[app]"
pipx ensurepath

say "Desktop launcher (sources your cloud key + uses grin's full path)"
APPS="$HOME/.local/share/applications"
ICONS="$HOME/.local/share/icons/hicolor/256x256/apps"
mkdir -p "$APPS" "$ICONS"
cp grin/app/assets/icon.png "$ICONS/grin.png" 2>/dev/null || true
cat > "$APPS/grin.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Version=1.0
Name=Grin
Comment=Autonomous red-team orchestrator (cloud-backed)
Icon=grin
Terminal=false
Categories=Development;Security;
Exec=bash -lc 'source "$HOME/.grin/deepseek.env" 2>/dev/null; exec "$HOME/.local/bin/grin" app'
DESKTOP
update-desktop-database "$APPS" 2>/dev/null || true

# Record where the source clone is, so the updater can find it.
mkdir -p "$HOME/.config/grin"
printf '%s\n' "$REPO" > "$HOME/.config/grin/source_repo"

# A working "Update Grin" button on the Desktop (wrapper with the resolved repo path; the
# install/*.desktop self-location breaks once copied off the repo).
if [ -d "$HOME/Desktop" ]; then
  mkdir -p "$HOME/.local/bin"
  cat > "$HOME/.local/bin/grin-update-term.sh" <<W
#!/usr/bin/env bash
"$REPO/scripts/update.sh"
echo; read -n1 -r -p "Update finished. Press any key to close."
W
  chmod +x "$HOME/.local/bin/grin-update-term.sh"
  cat > "$HOME/Desktop/Update Grin.desktop" <<DESK
[Desktop Entry]
Type=Application
Version=1.0
Name=Update Grin
Comment=Pull the latest Grin and reinstall
Icon=system-software-update
Terminal=false
Categories=Development;Security;
Exec=x-terminal-emulator -e $HOME/.local/bin/grin-update-term.sh
DESK
  chmod +x "$HOME/Desktop/Update Grin.desktop"
  gio set "$HOME/Desktop/Update Grin.desktop" metadata::trusted true 2>/dev/null || true
fi

say "Done"
echo "Launch 'Grin' from your applications menu. It reads your DeepSeek key from ~/.grin/deepseek.env."
echo "Update any time with: $SCRIPT_DIR/update.sh  (or the 'Update Grin' launcher)."
