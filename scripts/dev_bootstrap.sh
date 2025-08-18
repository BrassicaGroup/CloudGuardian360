#!/usr/bin/env bash
set -euo pipefail
echo "[*] Starting Postgres and API with docker compose..."
docker compose up -d
echo "[*] Waiting 10s for DB to be ready..."
sleep 10
echo "[*] API should be available at http://localhost:8080/docs"
