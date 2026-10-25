#!/usr/bin/env bash

set -e

CAPE_DIR="/opt/CAPEv2"

echo "======================================"
echo "        CAPE SANDBOX RESET"
echo "======================================"

# Require root privileges
if [ "$EUID" -ne 0 ]; then
    echo "This script requires administrative privileges."
    echo "Run:"
    echo "  sudo $PWD/reset-cape.sh"
    exit 1
fi

if [ ! -d "$CAPE_DIR/storage" ]; then
    echo "CAPE storage directory not found: $CAPE_DIR/storage"
    exit 1
fi

echo "WARNING: this deletes CAPE databases, stored analyses, binaries, temporary files, and logs."
read -r -p "Type RESET to continue: " confirmation
if [ "$confirmation" != "RESET" ]; then
    echo "Reset cancelled."
    exit 1
fi

echo "[1/7] Stopping CAPE..."
systemctl stop cape.service

echo "[2/7] Verifying CAPE/Cuckoo processes stopped..."
if systemctl is-active --quiet cape.service; then
    echo "CAPE is still active; refusing to delete its data."
    exit 1
fi

echo "[3/7] Removing CAPE databases..."
find "$CAPE_DIR" -maxdepth 3 -type f \
    \( -name "*.db" -o -name "cuckoo.db" \) \
    -print -delete

echo "[4/7] Removing old analysis data..."
rm -rf "$CAPE_DIR/storage/analyses/"*
rm -rf "$CAPE_DIR/storage/binaries/"*
rm -rf "$CAPE_DIR/storage/processed/"*
rm -rf "$CAPE_DIR/storage/zip/"*
rm -rf /tmp/cuckoo-tmp/*
rm -rf /tmp/cuckoo/*
rm -rf /tmp/cape-tmp/*

echo "[5/7] Cleaning logs..."
rm -rf "$CAPE_DIR/log/"*
rm -rf "$CAPE_DIR/logs/"*

echo "[6/7] Starting CAPE..."
systemctl daemon-reload
systemctl start cape.service
sleep 5

echo "[7/7] Checking CAPE..."
systemctl --no-pager --full status cape.service | head -20

echo
echo "Checking tasks..."
curl -sS http://127.0.0.1:8000/apiv2/tasks/list/ || true

echo
echo "======================================"
echo "       CAPE RESET COMPLETED"
echo "======================================"
