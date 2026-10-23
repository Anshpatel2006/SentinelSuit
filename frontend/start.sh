#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELECTION="${1:-all}"
RANSOMWARE_PORT="${RANSOMWARE_PORT:-8080}"
PHISHING_PORT="${PHISHING_PORT:-8001}"
IDS_PORT="${IDS_PORT:-8002}"
VULNSCAN_PORT="${VULNSCAN_PORT:-8765}"
VITE_PORT="${VITE_PORT:-3000}"
OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11434}"
OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://127.0.0.1:11434}"
OLLAMA_MODEL="${OLLAMA_MODEL:-llama3:latest}"
CAPE_URL="${CAPE_URL:-http://127.0.0.1:8000}"
RANSOMWARE_PYTHON="${RANSOMWARE_PYTHON:-$ROOT/../Ransomware/.venv/bin/python}"
PHISHING_PYTHON="${PHISHING_PYTHON:-$ROOT/../phising link/backend/.venv/bin/python}"
IDS_PYTHON="${IDS_PYTHON:-$ROOT/../ids/SentinelIDS/.venv/bin/python}"
VULNSCAN_PYTHON="${VULNSCAN_PYTHON:-$ROOT/../Al-VulnScan/.venv/bin/python}"
CHILD_PIDS=()

cleanup() {
  local pid
  for pid in "${CHILD_PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in "${CHILD_PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
}
trap cleanup INT TERM EXIT

start_ollama() {
  local attempt
  if ! command -v curl >/dev/null 2>&1; then
    echo "Ollama not started: curl is required to check its local API."
    return 0
  fi
  if curl -fsS --connect-timeout 1 --max-time 2 \
    "${OLLAMA_BASE_URL%/}/api/tags" >/dev/null 2>&1; then
    echo "Ollama is already responding at $OLLAMA_BASE_URL (configured model: $OLLAMA_MODEL)."
    return 0
  fi
  if ! command -v ollama >/dev/null 2>&1; then
    echo "Ollama not started: install Ollama or start it manually."
    return 0
  fi

  (
    export OLLAMA_HOST
    exec ollama serve
  ) &
  CHILD_PIDS+=("$!")
  echo "Ollama starting at $OLLAMA_BASE_URL (configured model: $OLLAMA_MODEL)..."
  for attempt in {1..15}; do
    if curl -fsS --connect-timeout 1 --max-time 2 \
      "${OLLAMA_BASE_URL%/}/api/tags" >/dev/null 2>&1; then
      echo "Ollama API is ready. Models are not downloaded automatically."
      return 0
    fi
    if ! kill -0 "${CHILD_PIDS[-1]}" 2>/dev/null; then
      echo "Ollama exited before its API became available."
      return 0
    fi
    sleep 1
  done
  echo "Ollama did not respond within 15 seconds; other services will still start."
}

start_cape() {
  local api_url="${CAPE_URL%/}/apiv2/tasks/list/"
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "CAPE not started: systemctl is unavailable; start CAPE manually."
    return 0
  fi
  if systemctl is-active --quiet cape.service; then
    echo "CAPE service is already active."
  else
    echo "Starting CAPE service (sudo may prompt for your password)..."
    if ! command -v sudo >/dev/null 2>&1; then
      echo "CAPE not started: sudo is unavailable. Run: systemctl start cape.service as an administrator."
      return 0
    fi
    if ! sudo systemctl start cape.service; then
      echo "CAPE service could not be started; other services will still start."
      return 0
    fi
    if ! systemctl is-active --quiet cape.service; then
      echo "CAPE service did not become active; check: systemctl status cape.service"
      return 0
    fi
    echo "CAPE service is active."
  fi

  if command -v curl >/dev/null 2>&1; then
    if curl -fsS --connect-timeout 2 --max-time 5 "$api_url" >/dev/null 2>&1; then
      echo "CAPE API is responding at $CAPE_URL."
    else
      echo "CAPE service is active, but its API did not respond at $CAPE_URL."
    fi
  fi
}

start_uvicorn() {
  local label="$1" directory="$2" python="$3" module="$4" port="$5" pythonpath="${6:-}"
  if [[ ! -d "$directory" || ! -x "$python" ]]; then
    echo "$label not started: project directory or configured Python environment is missing."
    return 0
  fi
  (
    cd "$directory"
    if [[ -n "$pythonpath" ]]; then
      export PYTHONPATH="$pythonpath"
    fi
    exec "$python" -m uvicorn "$module" --host 127.0.0.1 --port "$port"
  ) &
  CHILD_PIDS+=("$!")
  echo "$label API starting at http://127.0.0.1:$port"
}

start_vulnscan() {
  local directory="$ROOT/../Al-VulnScan"
  if [[ ! -d "$directory" || ! -x "$VULNSCAN_PYTHON" ]]; then
    echo "AI-VulnScan API not started: project directory or configured Python environment is missing."
    return 0
  fi
  (
    cd "$directory"
    export AL_VULNSCAN_CORS_ORIGINS="${AL_VULNSCAN_CORS_ORIGINS:-http://127.0.0.1:$VITE_PORT,http://localhost:$VITE_PORT}"
    exec "$VULNSCAN_PYTHON" api.py --port "$VULNSCAN_PORT"
  ) &
  CHILD_PIDS+=("$!")
  echo "AI-VulnScan API starting at http://127.0.0.1:$VULNSCAN_PORT"
}

start_ids() {
  local directory="$ROOT/../ids/SentinelIDS"
  if [[ ! -d "$directory" || ! -x "$IDS_PYTHON" ]]; then
    echo "SentinelIDS API not started: project directory or configured Python environment is missing."
    return 0
  fi
  (
    cd "$directory"
    export IDS_ACTIVE_SCAN_ENABLED="${IDS_ACTIVE_SCAN_ENABLED:-0}"
    exec "$IDS_PYTHON" -m uvicorn api.app:app --host 127.0.0.1 --port "$IDS_PORT"
  ) &
  CHILD_PIDS+=("$!")
  echo "SentinelIDS API starting at http://127.0.0.1:$IDS_PORT (active follow-up scans default to disabled)"
}

start_frontend() {
  if [[ ! -x "$ROOT/frontend/node_modules/.bin/vite" ]]; then
    echo "Frontend not started: install its locked dependencies with npm ci in frontend/frontend."
    return 0
  fi
  (
    cd "$ROOT/frontend"
    export VITE_RANSOMWARE_API_URL="${VITE_RANSOMWARE_API_URL:-http://127.0.0.1:$RANSOMWARE_PORT/api/v1}"
    export VITE_PHISHING_API_URL="${VITE_PHISHING_API_URL:-http://127.0.0.1:$PHISHING_PORT/api}"
    export VITE_IDS_API_URL="${VITE_IDS_API_URL:-http://127.0.0.1:$IDS_PORT}"
    export VITE_VULNSCAN_API_URL="${VITE_VULNSCAN_API_URL:-http://127.0.0.1:$VULNSCAN_PORT}"
    exec npm run dev -- --host 127.0.0.1 --port "$VITE_PORT"
  ) &
  CHILD_PIDS+=("$!")
  echo "SentinelSuite frontend starting at http://127.0.0.1:$VITE_PORT"
}

case "$SELECTION" in
  all)
    start_ransomware() { start_uvicorn "Ransomware" "$ROOT/../Ransomware" "$RANSOMWARE_PYTHON" "malware_platform.api.app:app" "$RANSOMWARE_PORT" "src"; }
    start_phishing() { start_uvicorn "Phishing Detection" "$ROOT/../phising link/backend" "$PHISHING_PYTHON" "main:app" "$PHISHING_PORT"; }
    start_cape
    start_ollama
    start_ransomware
    start_phishing
    start_ids
    start_vulnscan
    start_frontend
    ;;
  ransomware)
    start_cape
    start_uvicorn "Ransomware" "$ROOT/../Ransomware" "$RANSOMWARE_PYTHON" "malware_platform.api.app:app" "$RANSOMWARE_PORT" "src"
    ;;
  phishing)
    start_uvicorn "Phishing Detection" "$ROOT/../phising link/backend" "$PHISHING_PYTHON" "main:app" "$PHISHING_PORT"
    ;;
  ids)
    start_ids
    ;;
  vulnscan)
    start_ollama
    start_vulnscan
    ;;
  cape)
    start_cape
    ;;
  ollama)
    start_ollama
    ;;
  frontend)
    start_frontend
    ;;
  *)
    echo "Usage: $0 [all|ransomware|phishing|ids|vulnscan|cape|ollama|frontend]" >&2
    exit 2
    ;;
esac

if [[ ${#CHILD_PIDS[@]} -gt 0 ]]; then
  wait
fi
