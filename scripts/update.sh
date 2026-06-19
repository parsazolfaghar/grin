#!/usr/bin/env bash
# update.sh — pull the latest Grin and reinstall. One-button update.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
REPO="$(dirname "$SCRIPT_DIR")"
cd "$REPO"
say() { printf '\n\033[1;32m== %s\033[0m\n' "$1"; }

if [ ! -d .git ]; then
  echo "This folder isn't a git clone, so it can't update itself."
  echo "Clone it properly: git clone https://github.com/parsazolfaghar/grin.git ~/grin"
  exit 1
fi

say "Pulling the latest grin"
git pull --ff-only

# Editable install means the pull already updated the code; reinstall picks up any new deps.
say "Reinstalling (picks up new dependencies)"
pipx install --force -e ".[app]"

say "Done — relaunch Grin from the menu."
