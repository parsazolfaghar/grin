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
BEFORE="$(git rev-parse --short HEAD 2>/dev/null || echo '?')"
git pull --ff-only
AFTER="$(git rev-parse --short HEAD 2>/dev/null || echo '?')"

# Editable install means the pull already updated the code; reinstall picks up any new deps.
say "Reinstalling (picks up new dependencies)"
pipx install --force -e ".[app]"

GRIN="$HOME/.local/bin/grin"

# A complete update touches all THREE layers, not just the Python code:
say "Re-deploying helpers into the arsenal containers (closers run there, not in the venv)"
"$GRIN" arsenal deploy 2>/dev/null || echo "  (arsenal not up / no docker — skipped)"

say "Syncing the Grin Brain (adds new learned plays without wiping what it learned)"
"$GRIN" brain seed 2>/dev/null || echo "  (brain sync skipped)"

say "Done — now on $("$GRIN" --version 2>/dev/null || echo grin) ($BEFORE -> $AFTER). Relaunch Grin from the menu."
