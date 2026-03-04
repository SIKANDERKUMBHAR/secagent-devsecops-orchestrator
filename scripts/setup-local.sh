#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${SECAGENT_REPO_URL:-https://github.com/SIKANDERKUMBHAR/secagent-devsecops-orchestrator.git}"
TARGET_DIR="${SECAGENT_INSTALL_DIR:-$HOME/secagent-devsecops-orchestrator}"
BIN_DIR="${SECAGENT_BIN_DIR:-$HOME/.local/bin}"
PROFILE_LINE="export PATH=\"$BIN_DIR:\$PATH\""
INSTALL_SCANNERS="${SECAGENT_INSTALL_SCANNERS:-1}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Error: missing required command '$1'. Please install it and rerun." >&2
    exit 1
  fi
}

install_venv_pkg_if_possible() {
  if command -v apt-get >/dev/null 2>&1; then
    local venv_pkg
    venv_pkg="python3-venv"
    if command -v python3 >/dev/null 2>&1; then
      local py_minor
      py_minor="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
      venv_pkg="python${py_minor}-venv"
    fi

    echo "Attempting to install virtualenv support package: ${venv_pkg}" >&2
    if command -v sudo >/dev/null 2>&1; then
      sudo apt-get update && sudo apt-get install -y "$venv_pkg" || true
    else
      apt-get update && apt-get install -y "$venv_pkg" || true
    fi
  fi
}

require_cmd git
require_cmd python3
require_cmd uname

ensure_path_in_shell_profiles() {
  local profile
  for profile in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [[ -f "$profile" ]]; then
      if ! grep -Fq "$PROFILE_LINE" "$profile"; then
        printf '\n# Added by secagent installer\n%s\n' "$PROFILE_LINE" >> "$profile"
      fi
    fi
  done

  if [[ ! -f "$HOME/.bashrc" ]]; then
    printf '# Added by secagent installer\n%s\n' "$PROFILE_LINE" > "$HOME/.bashrc"
  fi
}

if [[ ! -d "$TARGET_DIR/.git" ]]; then
  git clone "$REPO_URL" "$TARGET_DIR"
else
  git -C "$TARGET_DIR" pull --ff-only
fi

if ! python3 -m venv "$TARGET_DIR/.venv"; then
  echo "python3 venv creation failed. Trying to install venv package..." >&2
  install_venv_pkg_if_possible
  python3 -m venv "$TARGET_DIR/.venv"
fi

"$TARGET_DIR/.venv/bin/pip" install --upgrade pip
"$TARGET_DIR/.venv/bin/pip" install -e "$TARGET_DIR[dev]"

"$TARGET_DIR/.venv/bin/secagent" version
"$TARGET_DIR/.venv/bin/secagent" validate-config --config "$TARGET_DIR/secagent.yml.example"

mkdir -p "$BIN_DIR"
cat > "$BIN_DIR/secagent" <<EOF
#!/usr/bin/env bash
exec "$TARGET_DIR/.venv/bin/secagent" "\$@"
EOF
chmod +x "$BIN_DIR/secagent"
ensure_path_in_shell_profiles

install_scanners() {
  echo "Installing scanner dependencies (semgrep, checkov, gitleaks, trivy)..." >&2

  "$TARGET_DIR/.venv/bin/pip" install --upgrade "setuptools<81"

  "$TARGET_DIR/.venv/bin/pip" install --upgrade semgrep==1.84.0 checkov==3.2.298

  cat > "$BIN_DIR/semgrep" <<EOF
#!/usr/bin/env bash
exec "$TARGET_DIR/.venv/bin/semgrep" "\$@"
EOF
  chmod +x "$BIN_DIR/semgrep"

  cat > "$BIN_DIR/checkov" <<EOF
#!/usr/bin/env bash
exec "$TARGET_DIR/.venv/bin/checkov" "\$@"
EOF
  chmod +x "$BIN_DIR/checkov"

  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64)
      ;;
    *)
      echo "Warning: gitleaks/trivy auto-install currently supports linux x86_64 only. Current arch: $arch" >&2
      return 0
      ;;
  esac

  require_cmd curl
  require_cmd tar

  local gitleaks_ver trivy_ver
  gitleaks_ver="8.23.3"
  trivy_ver="0.69.2"

  curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors \
    "https://github.com/gitleaks/gitleaks/releases/download/v${gitleaks_ver}/gitleaks_${gitleaks_ver}_linux_x64.tar.gz" \
    -o /tmp/gitleaks.tgz
  tar -xzf /tmp/gitleaks.tgz -C "$BIN_DIR" gitleaks
  chmod +x "$BIN_DIR/gitleaks"

  curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors \
    "https://github.com/aquasecurity/trivy/releases/download/v${trivy_ver}/trivy_${trivy_ver}_Linux-64bit.tar.gz" \
    -o /tmp/trivy.tgz
  tar -xzf /tmp/trivy.tgz -C "$BIN_DIR" trivy
  chmod +x "$BIN_DIR/trivy"

  echo "Scanner installation complete." >&2
}

verify_scanners() {
  local missing=0
  for cmd in semgrep checkov gitleaks trivy; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "Warning: scanner '$cmd' is not in PATH." >&2
      missing=1
    fi
  done

  if [[ "$missing" -eq 1 ]]; then
    echo "Tip: open a new shell or run: export PATH=\"$BIN_DIR:\$PATH\"" >&2
  fi
}

if [[ "$INSTALL_SCANNERS" == "1" ]]; then
  install_scanners
fi

verify_scanners

cat <<EOF

secagent local setup complete.

Global launcher installed at:
  $BIN_DIR/secagent

Use these commands:
  secagent version
  secagent scan --target https://github.com/vulnerable-apps/vulnerable-rest-api.git --config "$TARGET_DIR/secagent.yml.example"
  secagent scan --target . --config "$TARGET_DIR/secagent.yml.example"

EOF

if ! echo ":$PATH:" | grep -q ":$BIN_DIR:"; then
  echo "Note: $BIN_DIR was added to ~/.bashrc (and ~/.zshrc if present)." >&2
  echo "Run this once in your current shell to use secagent immediately:" >&2
  echo "  export PATH=\"$BIN_DIR:\$PATH\"" >&2
fi
