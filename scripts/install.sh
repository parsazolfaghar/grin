#!/usr/bin/env bash
# install.sh — public one-liner bootstrap. Clones grin and runs the full installer.
#
#   curl -fsSL https://raw.githubusercontent.com/parsazolfaghar/grin/main/scripts/install.sh | bash
#
# Brings the whole package: the grin CLI + desktop app, the Kali/BlackArch arsenal helpers, and the
# seeded Grin Brain. You bring your own API key — grin never proxies a model and never sees your
# traffic. Authorized security testing only (see LICENSE).
set -euo pipefail

REPO_URL="${GRIN_REPO_URL:-https://github.com/parsazolfaghar/grin.git}"
DEST="${GRIN_DIR:-$HOME/grin}"
say() { printf '\n\033[1;33m== %s\033[0m\n' "$1"; }

command -v git >/dev/null 2>&1 || { echo "git is required (sudo apt install -y git)"; exit 1; }

if [ -d "$DEST/.git" ]; then
  say "grin already present at $DEST — updating"
  git -C "$DEST" pull --ff-only
else
  say "Cloning grin -> $DEST"
  git clone --depth 1 "$REPO_URL" "$DEST"
fi

if [ ! -f "$DEST/scripts/install-on-kali.sh" ]; then
  echo "installer not found in clone — aborting"; exit 1
fi

say "Running the installer (apt deps + app + arsenal + brain)"
bash "$DEST/scripts/install-on-kali.sh"

cat <<'NEXT'

== Almost there ==
1. Bring your own API key. Create ~/.grin/deepseek.env with an OpenAI-compatible endpoint, e.g.:
     GRIN_MODEL_BACKEND=openai
     GRIN_MODEL_URL=https://api.deepseek.com/v1
     GRIN_MODEL_API_KEY=sk-...           # YOUR key. grin never proxies or sees your traffic.
   (Or run a local model with Ollama and skip the cloud key entirely.)
2. Launch "Grin" from your applications menu.
3. Update any time with the "Update Grin" button (or scripts/update.sh).

Authorized security testing only. You are responsible for what you do with this. See LICENSE.
NEXT
