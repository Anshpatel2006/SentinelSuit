#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$ROOT_DIR/.venv"
LOG_DIR="$ROOT_DIR/logs"
BACKEND_LOG="$LOG_DIR/backend.log"
FRONTEND_LOG="$LOG_DIR/frontend.log"

# CAPE settings can be overridden by environment variables before startup.
export CAPE_URL="${CAPE_URL:-http://127.0.0.1:8000}"
export CAPE_MACHINE="${CAPE_MACHINE:-cuckoo1}"
export CAPE_PACKAGE="${CAPE_PACKAGE:-exe}"
export CAPE_STORAGE="${CAPE_STORAGE:-/opt/CAPEv2/storage/analyses}"
export CAPE_POLL_INTERVAL="${CAPE_POLL_INTERVAL:-10}"
export API_HOST="${API_HOST:-127.0.0.1}"
export API_PORT="${API_PORT:-8080}"

mkdir -p "$LOG_DIR"

SUDO_CMD=(sudo -n)
if ! sudo -n -v >/dev/null 2>&1 && [[ -t 0 ]]; then
  echo "Administrator access is required to start the CAPE VM."
  if sudo -v; then
    SUDO_CMD=(sudo)
  fi
fi

echo "Checking CAPE virtualization services..."
if command -v systemctl >/dev/null 2>&1; then
  if ! systemctl is-active --quiet libvirtd 2>/dev/null && \
     ! systemctl is-active --quiet virtqemud 2>/dev/null; then
    "${SUDO_CMD[@]}" systemctl start libvirtd 2>/dev/null || \
      "${SUDO_CMD[@]}" systemctl start virtqemud 2>/dev/null || \
      echo "Warning: libvirt is not active or sudo permission is unavailable."
  fi

  if systemctl is-active --quiet cape 2>/dev/null; then
    echo "CAPE service: active"
  elif "${SUDO_CMD[@]}" systemctl start cape 2>/dev/null; then
    echo "CAPE service: started"
  else
    echo "Warning: CAPE service is not active; dynamic analysis will be unavailable."
  fi
else
  echo "Warning: systemctl is unavailable; CAPE service was not started."
fi

if command -v virsh >/dev/null 2>&1; then
  vm_state="$("${SUDO_CMD[@]}" virsh domstate "$CAPE_MACHINE" 2>/dev/null || virsh domstate "$CAPE_MACHINE" 2>/dev/null || true)"
  if [[ "$vm_state" == "running" ]]; then
    echo "CAPE VM ($CAPE_MACHINE): running"
  else
    echo "CAPE VM ($CAPE_MACHINE) is not running; starting it..."
    if virsh start "$CAPE_MACHINE" >/dev/null 2>&1 || \
       "${SUDO_CMD[@]}" virsh start "$CAPE_MACHINE" >/dev/null 2>&1; then
      for i in $(seq 1 30); do
        vm_state="$("${SUDO_CMD[@]}" virsh domstate "$CAPE_MACHINE" 2>/dev/null || virsh domstate "$CAPE_MACHINE" 2>/dev/null || true)"
        if [[ "$vm_state" == "running" ]]; then
          echo "CAPE VM ($CAPE_MACHINE): running"
          break
        fi
        sleep 1
      done
    fi
    if [[ "$vm_state" != "running" ]]; then
      echo "Warning: CAPE VM ($CAPE_MACHINE) could not be started."
    fi
  fi
else
  echo "Warning: virsh is unavailable; CAPE VM was not checked."
fi

if curl -fsS "$CAPE_URL/apiv2/tasks/list/" >/dev/null 2>&1; then
  echo "CAPE API: reachable at $CAPE_URL"
else
  echo "Warning: CAPE API is not reachable at $CAPE_URL."
fi

if [[ ! -d "$VENV_DIR" ]]; then
  echo "Creating Python virtual environment at $VENV_DIR"
  python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip >/dev/null 2>&1
pip install -e "$ROOT_DIR" >/dev/null 2>&1

if ! pgrep -f "python -m malware_platform.api.server" >/dev/null 2>&1; then
  echo "Starting backend API..."
  nohup python -m malware_platform.api.server >"$BACKEND_LOG" 2>&1 &
fi

for i in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${API_PORT}/api/v1/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if [[ ! -d "$ROOT_DIR/frontend/node_modules" ]]; then
  echo "Installing frontend dependencies..."
  (cd "$ROOT_DIR/frontend" && npm install >/dev/null 2>&1)
fi

if ! pgrep -f "vite --host 0.0.0.0" >/dev/null 2>&1; then
  echo "Starting frontend dev server..."
  (cd "$ROOT_DIR/frontend" && nohup npm run dev -- --host 0.0.0.0 >"$FRONTEND_LOG" 2>&1 &)
fi

for i in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:5173" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

printf "\nBackend: http://127.0.0.1:8080\n"
printf "Frontend: http://127.0.0.1:5173\n"
printf "Backend log: %s\n" "$BACKEND_LOG"
printf "Frontend log: %s\n" "$FRONTEND_LOG"
