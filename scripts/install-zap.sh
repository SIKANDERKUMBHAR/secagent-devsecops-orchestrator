#!/usr/bin/env bash
set -euo pipefail

IMAGE="${SECAGENT_ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
CONTAINER="${SECAGENT_ZAP_CONTAINER:-secagent-zap}"
HOST_PORT="${SECAGENT_ZAP_HOST_PORT:-8090}"
ZAP_PORT="${SECAGENT_ZAP_PORT:-8090}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Error: missing required command '$1'." >&2
    exit 1
  fi
}

usage() {
  cat <<'EOF'
Usage:
  scripts/install-zap.sh [--pull-only] [--start]

Options:
  --pull-only   Pull ZAP image only (default)
  --start       Pull and start/restart sidecar container

Environment overrides:
  SECAGENT_ZAP_IMAGE      (default: ghcr.io/zaproxy/zaproxy:stable)
  SECAGENT_ZAP_CONTAINER  (default: secagent-zap)
  SECAGENT_ZAP_HOST_PORT  (default: 8090)
  SECAGENT_ZAP_PORT       (default: 8090)
EOF
}

START=0
if [[ "${1:-}" == "--start" ]]; then
  START=1
elif [[ "${1:-}" == "--pull-only" || -z "${1:-}" ]]; then
  START=0
elif [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
else
  echo "Unknown option: ${1:-}" >&2
  usage >&2
  exit 2
fi

require_cmd docker
require_cmd curl

echo "Pulling ZAP image: $IMAGE"
docker pull "$IMAGE"

if [[ "$START" -eq 0 ]]; then
  echo "ZAP image is ready."
  exit 0
fi

echo "Starting ZAP sidecar: $CONTAINER"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" -p "$HOST_PORT:$ZAP_PORT" "$IMAGE" \
  zap.sh -daemon -host 0.0.0.0 -port "$ZAP_PORT" \
  -config api.disablekey=true \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true \
  -config autoupdate.checkOnStart=false \
  -config autoupdate.installAddonUpdates=false >/dev/null

for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${HOST_PORT}/JSON/core/view/version/" >/dev/null 2>&1; then
    echo "ZAP sidecar is ready at http://127.0.0.1:${HOST_PORT}"
    exit 0
  fi
  sleep 2
done

echo "ZAP sidecar did not become ready in time." >&2
exit 1
