#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

SCANNER_API_KEY="${SCANNER_API_KEY:-netscope-key}"
export SCANNER_API_KEY
HOST_URL="http://localhost:8080"

printf 'Starting NetScope with Docker Compose...\n'
docker compose up --build -d

printf 'Waiting for the web UI to become available at %s\n' "$HOST_URL"
for i in $(seq 1 12); do
  if curl -sSf "$HOST_URL" >/dev/null 2>&1; then
    printf 'Web UI is available.\n'
    break
  fi
  sleep 1
  if [ "$i" -eq 12 ]; then
    printf 'Timed out waiting for web UI, but continuing.\n'
  fi
 done

if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$HOST_URL" >/dev/null 2>&1 || true
elif command -v sensible-browser >/dev/null 2>&1; then
  sensible-browser "$HOST_URL" >/dev/null 2>&1 || true
elif command -v gio >/dev/null 2>&1; then
  gio open "$HOST_URL" >/dev/null 2>&1 || true
else
  printf 'Browser open command not found. Open %s manually.\n' "$HOST_URL"
fi

printf 'NetScope is running. Stop it with: docker compose down\n'
