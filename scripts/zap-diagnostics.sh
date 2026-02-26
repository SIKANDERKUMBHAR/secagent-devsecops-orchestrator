#!/usr/bin/env bash
set -u

API_URL="${SECAGENT_ZAP_API_URL:-http://127.0.0.1:8090}"
TARGET_URL="${SECAGENT_ZAP_TARGET_URL:-http://127.0.0.1:3000}"
CONTAINER_NAME="${SECAGENT_ZAP_CONTAINER:-secagent-zap}"
OUTPUT_FILE=""
SECAGENT_CONFIG=""

usage() {
  cat <<'EOF'
Usage: scripts/zap-diagnostics.sh [options]

Options:
  --api-url URL          ZAP API base URL (default: http://127.0.0.1:8090)
  --target-url URL       Application base URL used by secagent DAST
  --container NAME       ZAP container name to inspect (default: secagent-zap)
  --config PATH          Optional secagent config for `secagent doctor --config`
  --output PATH          Write report to this file
  -h, --help             Show this help

Environment overrides:
  SECAGENT_ZAP_API_URL, SECAGENT_ZAP_TARGET_URL, SECAGENT_ZAP_CONTAINER

Example:
  scripts/zap-diagnostics.sh --api-url http://127.0.0.1:8090 --target-url http://127.0.0.1:3000 --config /home/ubuntu/secagent/secagent-dast.yml
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-url)
      API_URL="$2"
      shift 2
      ;;
    --target-url)
      TARGET_URL="$2"
      shift 2
      ;;
    --container)
      CONTAINER_NAME="$2"
      shift 2
      ;;
    --config)
      SECAGENT_CONFIG="$2"
      shift 2
      ;;
    --output)
      OUTPUT_FILE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$OUTPUT_FILE" ]]; then
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  OUTPUT_FILE="zap-diagnostics-${timestamp}.txt"
fi

touch "$OUTPUT_FILE" || {
  echo "Unable to write output file: $OUTPUT_FILE" >&2
  exit 2
}

log() {
  printf '%s\n' "$*" | tee -a "$OUTPUT_FILE"
}

section() {
  log ""
  log "===== $* ====="
}

run_capture() {
  local title="$1"
  shift
  section "$title"
  log "Command: $*"
  set +e
  local output
  output="$("$@" 2>&1)"
  local rc=$?
  set -e
  if [[ -n "$output" ]]; then
    printf '%s\n' "$output" | tee -a "$OUTPUT_FILE"
  fi
  log "Exit code: $rc"
  return 0
}

curl_check() {
  local title="$1"
  local url="$2"
  section "$title"
  log "URL: $url"
  if ! command -v curl >/dev/null 2>&1; then
    log "curl not found in PATH"
    return 0
  fi

  set +e
  local body http_code rc
  body="$(curl -sS --max-time 20 -w $'\nHTTP_CODE:%{http_code}\n' "$url")"
  rc=$?
  set -e

  if [[ $rc -ne 0 ]]; then
    log "curl failed with exit code: $rc"
    printf '%s\n' "$body" | tee -a "$OUTPUT_FILE"
    return 0
  fi

  http_code="$(printf '%s\n' "$body" | sed -n 's/^HTTP_CODE://p')"
  log "HTTP status: ${http_code:-unknown}"
  printf '%s\n' "$body" | sed '/^HTTP_CODE:/d' | tee -a "$OUTPUT_FILE"
  return 0
}

set -e

section "Context"
log "Report file: $OUTPUT_FILE"
log "Started at (UTC): $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
log "API URL: $API_URL"
log "Target URL: $TARGET_URL"
log "Container name: $CONTAINER_NAME"

run_capture "Host identity" uname -a
run_capture "OS release" sh -c 'if [ -f /etc/os-release ]; then cat /etc/os-release; else echo "No /etc/os-release"; fi'
run_capture "Hostname and users" sh -c 'hostname; whoami; id'
run_capture "Proxy environment" sh -c 'env | grep -Ei "(_proxy=|_PROXY=|NO_PROXY=|no_proxy=)" || true'

run_capture "Tool availability" sh -c 'command -v secagent || true; command -v curl || true; command -v docker || true'
run_capture "secagent version" sh -c 'secagent version || true'

if [[ -n "$SECAGENT_CONFIG" ]]; then
  run_capture "secagent doctor" sh -c "secagent doctor --config '$SECAGENT_CONFIG' || true"
fi

curl_check "ZAP API version from host" "$API_URL/JSON/core/view/version/"
curl_check "ZAP API passive queue from host" "$API_URL/JSON/pscan/view/recordsToScan/"
curl_check "ZAP API alerts from host" "$API_URL/JSON/core/view/alerts/"

if command -v docker >/dev/null 2>&1; then
  run_capture "docker ps for ZAP container" sh -c "docker ps --filter name='$CONTAINER_NAME' --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'"
  run_capture "docker inspect ZAP container" sh -c "docker inspect '$CONTAINER_NAME' || true"
  run_capture "ZAP container recent logs" sh -c "docker logs --tail 200 '$CONTAINER_NAME' || true"
  run_capture "ZAP API version from inside container" sh -c "docker exec '$CONTAINER_NAME' sh -lc 'wget -qO- http://127.0.0.1:8080/JSON/core/view/version/ 2>/dev/null || true' || true"
else
  section "Docker checks"
  log "docker command not found; skipping container inspection"
fi

section "Troubleshooting hints"
log "- If host call fails but in-container call succeeds, check host reverse proxy/firewall/port mapping."
log "- If both host and in-container calls fail, check ZAP startup args and logs for API binding/auth issues."
log "- If HTTP 502 appears intermittently, increase zap.api_retries and zap.api_retry_delay_seconds in config."
log "- Ensure zap.api_url matches published host port (for example 8090 when using -p 8090:8080)."

section "Done"
log "Completed at (UTC): $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
log "Saved report: $OUTPUT_FILE"
