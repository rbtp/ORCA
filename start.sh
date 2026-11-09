#!/bin/bash
# Start ORCA (after it has been installed with install.sh).
cd "$(dirname "$0")"
echo "[ORCA] Starting..."
docker compose up -d || { echo "[ORCA] Failed to start. Is Docker running?"; exit 1; }
url=$(grep -E '^ORCA_SERVER_URL=' .env 2>/dev/null | cut -d= -f2-)
echo "[ORCA] Running: ${url:-https://localhost}"
