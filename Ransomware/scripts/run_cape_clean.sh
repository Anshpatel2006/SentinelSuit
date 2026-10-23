#!/bin/bash

set -e

CAPEV2="/opt/CAPEv2"
ANALYSES="$CAPEV2/storage/analyses"
PROJECT="/media/ansh/2096AA8B96AA6150/AI-Malware-Analysis-Platform-COMPLETE-FLOW/AI-Malware-Analysis-Platform"
PYTHON="$PROJECT/venv/bin/python"

# Keep analyses newer than this many days
KEEP_DAYS=2

echo "========================================"
echo " CAPE CLEAN + FRESH SNAPSHOT RUN"
echo "========================================"

echo
echo "[1] Stopping any manually running VM..."

if sudo virsh domstate cuckoo1 2>/dev/null | grep -q "running"; then
    echo "[VM] Destroying running cuckoo1..."
    sudo virsh destroy cuckoo1
fi

echo "[VM] Current state:"
sudo virsh domstate cuckoo1

echo
echo "[2] Cleaning old CAPE analysis directories..."
echo "[CLEANUP] Keeping last $KEEP_DAYS days"

sudo find "$ANALYSES" \
    -mindepth 1 \
    -maxdepth 1 \
    -type d \
    -mtime +"$KEEP_DAYS" \
    -print \
    -exec rm -rf {} \;

echo
echo "[3] Current CAPE storage:"
sudo du -sh "$ANALYSES"

echo
echo "[4] Checking snapshot..."

if sudo virsh snapshot-list cuckoo1 | grep -q "clean-win10"; then
    echo "[SNAPSHOT] clean-win10 exists."
else
    echo "[ERROR] clean-win10 snapshot does not exist!"
    exit 1
fi

echo
echo "[5] Checking CAPE service..."

sudo systemctl restart cape
sleep 3

if ! systemctl is-active --quiet cape; then
    echo "[ERROR] CAPE service failed to start."
    sudo systemctl status cape --no-pager
    exit 1
fi

echo "[CAPE] Service is running."

echo
echo "[6] Starting pipeline..."

SAMPLE="$1"

if [ -z "$SAMPLE" ]; then
    echo "Usage:"
    echo "  ./run_cape_clean.sh <sample>"
    exit 1
fi

if [ ! -f "$SAMPLE" ]; then
    echo "[ERROR] Sample not found: $SAMPLE"
    exit 1
fi

echo "[SAMPLE] $SAMPLE"
echo
echo "[IMPORTANT] CAPE will automatically use:"
echo "           VM       : cuckoo1"
echo "           Snapshot : clean-win10"
echo

cd "$PROJECT"

exec "$PYTHON" flow_pipeline.py "$SAMPLE"
