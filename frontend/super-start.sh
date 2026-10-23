#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Starting SentinelSuite through start.sh. The all profile also starts Ollama and CAPE if needed."
echo "This wrapper does not reset/delete CAPE data or enable packet capture."
exec "$ROOT/start.sh" "${1:-all}"
