#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${SECAGENT_REPO_URL:-https://github.com/SIKANDERKUMBHAR/secagent-devsecops-orchestrator.git}"
TARGET_DIR="${SECAGENT_INSTALL_DIR:-$HOME/secagent-devsecops-orchestrator}"

if [[ ! -d "$TARGET_DIR/.git" ]]; then
  git clone "$REPO_URL" "$TARGET_DIR"
else
  git -C "$TARGET_DIR" pull --ff-only
fi

python3 -m venv "$TARGET_DIR/.venv"
"$TARGET_DIR/.venv/bin/pip" install --upgrade pip
"$TARGET_DIR/.venv/bin/pip" install -e "$TARGET_DIR[dev]"

"$TARGET_DIR/.venv/bin/secagent" version
"$TARGET_DIR/.venv/bin/secagent" validate-config --config "$TARGET_DIR/secagent.yml.example"

cat <<EOF

secagent local setup complete.

Use these commands:
  source "$TARGET_DIR/.venv/bin/activate"
  secagent scan --target . --config "$TARGET_DIR/secagent.yml.example"

EOF
