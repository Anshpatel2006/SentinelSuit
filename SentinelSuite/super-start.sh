#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPE_URL="${CAPE_URL:-http://127.0.0.1:8000}"
CAPE_STORAGE="${CAPE_STORAGE:-/opt/CAPEv2/storage/analyses}"
APP_USER="${SUDO_USER:-${USER:-ansh}}"
IDS_INTERFACE="${IDS_INTERFACE:-$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}')}"
IDS_INTERFACE="${IDS_INTERFACE:-wlp4s0}"

if [[ "$EUID" -ne 0 ]]; then
  echo "Run this script with sudo so CAPE and raw packet capture can start."
  echo "sudo ./super-start.sh"
  exit 1
fi

if ! id "$APP_USER" >/dev/null 2>&1; then
  echo "Application user not found: $APP_USER"
  exit 1
fi

stop_processes() {
  local pattern pid
  for pattern in \
    "uvicorn malware_platform.api.app:app" \
    "uvicorn main:app" \
    "uvicorn api.app:app" \
    "$ROOT/frontend/node_modules/.bin/vite" \
    "ids.packet_capture"; do
    while read -r pid; do
      [[ -z "$pid" ]] && continue
      echo "Stopping existing process $pid ($pattern)"
      kill "$pid" 2>/dev/null || true
    done < <(ps -eo pid=,args= | awk -v pattern="$pattern" '$0 ~ pattern {print $1}')
  done
  sleep 2
}

delete_pending_tasks() {
  local task_ids task_id response
  task_ids="$(
    curl -fsS --max-time 10 "$CAPE_URL/apiv2/tasks/list/" |
      python3 -c '
import json, sys
payload = json.load(sys.stdin)
for task in payload.get("data", []):
    if str(task.get("status", "")).lower() in {"pending", "queued", "submitted"}:
        print(task.get("id"))
'
  )"
  while read -r task_id; do
    [[ -z "$task_id" ]] && continue
    response="$(curl -fsS --max-time 10 "$CAPE_URL/apiv2/tasks/delete/$task_id/pending/" || true)"
    echo "Deleted CAPE pending task $task_id: ${response:-no response}"
  done <<< "$task_ids"
}

remove_memory_dumps() {
  if [[ ! -d "$CAPE_STORAGE" ]]; then
    echo "CAPE storage not found; skipping memory dump cleanup: $CAPE_STORAGE"
    return
  fi
  echo "Removing previous CAPE memory dumps from $CAPE_STORAGE"
  find "$CAPE_STORAGE" -type f -name "memory.dmp" -print -delete
}

echo "Stopping existing SentinelSuite services..."
stop_processes

echo "Stopping CAPE services..."
systemctl stop cape-web.service cape.service cape-rooter.service || true
sleep 2

echo "Starting CAPE services..."
systemctl start cape-rooter.service cape.service cape-web.service

cape_ready=0
for attempt in $(seq 1 30); do
  if curl -fsS --max-time 2 "$CAPE_URL/apiv2/cuckoo/status/" >/dev/null 2>&1; then
    cape_ready=1
    break
  fi
  sleep 1
done

if [[ "$cape_ready" -ne 1 ]]; then
  echo "CAPE web API did not become ready at $CAPE_URL."
  systemctl --no-pager --full status cape-web.service || true
  exit 1
fi

echo "CAPE web API is ready at $CAPE_URL"
delete_pending_tasks
remove_memory_dumps
machines=$(curl -fsS --max-time 5 "$CAPE_URL/apiv2/machines/list/" || true)
if [[ "$machines" == *'Machine list API is disabled'* ]]; then
  echo "CAPE machine listing is disabled; the CAPE scheduler will use configured machines."
else
  echo "CAPE machine state: $machines"
fi

echo "Starting SentinelSuite application services as $APP_USER..."
sudo -u "$APP_USER" -H env CAPE_URL="$CAPE_URL" IDS_CAPTURE_ENABLED=0 \
  bash -lc "cd '$ROOT' && ./start.sh" &
app_pid=$!

echo "Starting live IDS capture on $IDS_INTERFACE..."
(
  cd "$ROOT/../SentinelIDS_Project_Vidisha/SentinelIDS"
  IDS_INTERFACE="$IDS_INTERFACE" .venv/bin/python -m ids.packet_capture
) &
capture_pid=$!

cleanup() {
  kill "$capture_pid" "$app_pid" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

printf '\nSentinelSuite is running.\n'
printf 'Frontend: http://127.0.0.1:3000/\n'
printf 'Ransomware API: http://127.0.0.1:8080\n'
printf 'Phishing API: http://127.0.0.1:8001\n'
printf 'IDS API: http://127.0.0.1:8002\n'
printf 'CAPE API: %s\n' "$CAPE_URL"
printf 'IDS interface: %s\n' "$IDS_INTERFACE"

wait
