#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPE_URL="${CAPE_URL:-http://127.0.0.1:8000}"
RANSOMWARE_PORT="${RANSOMWARE_PORT:-8080}"
PHISHING_PORT="${PHISHING_PORT:-8001}"
IDS_PORT="${IDS_PORT:-8002}"
IDS_CAPTURE_ENABLED="${IDS_CAPTURE_ENABLED:-1}"
CAPTURE_PID=""
CHILD_PIDS=()

stop_existing_apps() {
  local pattern pid
  for pattern in \
    "uvicorn malware_platform.api.app:app" \
    "uvicorn main:app" \
    "uvicorn api.app:app" \
    "$ROOT/frontend/node_modules/.bin/vite"; do
    while read -r pid; do
      [[ -z "$pid" || "$pid" == "$$" ]] && continue
      echo "Stopping existing process $pid ($pattern)"
      kill "$pid" 2>/dev/null || true
    done < <(ps -eo pid=,args= | awk -v pattern="$pattern" '$0 ~ pattern {print $1}')
  done
  sleep 1
}

start_packet_capture() {
  if [[ "$IDS_CAPTURE_ENABLED" != "1" ]]; then
    echo "Live packet capture disabled (IDS_CAPTURE_ENABLED=$IDS_CAPTURE_ENABLED)."
    return
  fi

  if [[ "$EUID" -ne 0 ]]; then
    echo "IDS API started, but live packet capture requires root or capture capabilities."
    echo "Run with sudo or set IDS_CAPTURE_ENABLED=0."
    return
  fi

  local capture_interface="${IDS_INTERFACE:-}"
  if [[ -z "$capture_interface" ]]; then
    capture_interface="$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}')"
  fi
  capture_interface="${capture_interface:-wlp4s0}"

  echo "Starting live packet capture on $capture_interface..."
  (
    cd "$ROOT/../SentinelIDS_Project_Vidisha/SentinelIDS"
    IDS_INTERFACE="$capture_interface" .venv/bin/python -m ids.packet_capture
  ) &
  CAPTURE_PID=$!
}

stop_existing_apps

if ! curl -fsS --max-time 5 "$CAPE_URL/apiv2/tasks/list/" >/dev/null; then
  echo "CAPE is unavailable at $CAPE_URL. Start CAPE before starting SentinelSuite."
  exit 1
fi

echo "CAPE is reachable at $CAPE_URL"

(
  cd "$ROOT/../AI-Malware-Analysis-Platform"
  PYTHONPATH=src .venv/bin/python -m uvicorn malware_platform.api.app:app --host 127.0.0.1 --port "$RANSOMWARE_PORT"
) &
CHILD_PIDS+=("$!")
(
  cd "$ROOT/../phishing_react_app_fixed/backend"
  .venv/bin/python -m uvicorn main:app --host 127.0.0.1 --port "$PHISHING_PORT"
) &
CHILD_PIDS+=("$!")
(
  cd "$ROOT/../SentinelIDS_Project_Vidisha/SentinelIDS"
  .venv/bin/python -m uvicorn api.app:app --host 127.0.0.1 --port "$IDS_PORT"
) &
CHILD_PIDS+=("$!")
(
  cd "$ROOT/frontend"
  npm run dev -- --host 127.0.0.1
) &
CHILD_PIDS+=("$!")

start_packet_capture

cleanup() {
  local pid
  if [[ -n "$CAPTURE_PID" ]]; then
    kill "$CAPTURE_PID" 2>/dev/null || true
  fi
  for pid in "${CHILD_PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup INT TERM EXIT

wait
