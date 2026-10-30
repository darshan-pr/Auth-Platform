#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/authplatform"

usage() {
  printf 'Usage: %s\n' "${0##*/}"
  printf 'Starts local Spring Boot with Postgres, Redis, and Mailpit in Docker.\n'
  printf 'Stop Spring Boot with Ctrl+C, then use ./stop.sh to stop Docker services.\n'
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ $# -ne 0 ]]; then
  usage >&2
  exit 2
fi

for command_name in docker; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'Required command not found: %s\n' "$command_name" >&2
    exit 1
  fi
done

if [[ ! -f "$BACKEND_DIR/.env" ]]; then
  if [[ ! -f "$BACKEND_DIR/.env.example" ]]; then
    printf 'Backend environment file is missing: %s/.env.example\n' "$BACKEND_DIR" >&2
    exit 1
  fi
  cp "$BACKEND_DIR/.env.example" "$BACKEND_DIR/.env"
  printf 'Created authplatform/.env from .env.example. Review its local development values.\n'
fi

if [[ ! -x "$BACKEND_DIR/mvnw" ]]; then
  printf 'Maven wrapper is missing or not executable: %s/mvnw\n' "$BACKEND_DIR" >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  printf 'Docker is not running. Start Docker Desktop, then rerun ./start.sh.\n' >&2
  exit 1
fi

printf 'Starting Postgres, Redis, and Mailpit...\n'
cd "$BACKEND_DIR"
if [[ -n "$(docker compose ps --status running -q backend)" ]]; then
  printf 'Stopping the previous Docker backend before running Spring Boot locally...\n'
  docker compose stop backend
fi
docker compose up -d --wait postgres redis mailpit

printf '\nStarting Spring Boot locally. Logs are shown in this terminal.\n'
printf 'Backend:   http://localhost:8080\n'
printf 'Health:    http://localhost:8080/actuator/health\n'
printf 'Swagger:   http://localhost:8080/swagger-ui/index.html\n'
printf 'OpenAPI:   http://localhost:8080/v3/api-docs\n'
printf 'Mailpit:   http://localhost:8025\n'
printf 'Stop Spring Boot with Ctrl+C. Use ./stop.sh to stop Docker services.\n\n'
exec ./mvnw spring-boot:run