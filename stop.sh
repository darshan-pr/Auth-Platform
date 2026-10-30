#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/authplatform"
if ! command -v docker >/dev/null 2>&1; then
  printf 'Required command not found: docker\n' >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  printf 'Docker is not running. Start Docker Desktop, then rerun ./stop.sh.\n' >&2
  exit 1
fi

env_file="$BACKEND_DIR/.env"
if [[ ! -f "$env_file" ]]; then
  env_file="$BACKEND_DIR/.env.example"
fi

(cd "$BACKEND_DIR" && docker compose --env-file "$env_file" down)
printf 'Stopped Docker services. Persistent volumes were kept.\n'
printf 'If Spring Boot is still running, stop it with Ctrl+C in its terminal.\n'