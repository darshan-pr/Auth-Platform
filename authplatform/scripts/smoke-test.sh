#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
MAILPIT_URL="${MAILPIT_URL:-http://127.0.0.1:8025}"
EMAIL="${EMAIL:-smoke-$(date +%s)@example.com}"
PASSWORD="SmokeStrong123!"

echo "Checking health"
curl --fail --silent "$BASE_URL/actuator/health" | jq -e '.status == "UP"' >/dev/null

echo "Console signup"
curl --fail --silent -X POST "$BASE_URL/api/console/auth/signup" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"Smoke Developer\",\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" >/dev/null

TOKEN=""
for _ in $(seq 1 10); do
  TOKEN="$(curl --fail --silent "$MAILPIT_URL/api/v1/messages" | jq -r --arg email "$EMAIL" '.messages[] | select(.To[0].Address == $email) | .Snippet' | sed 's/.*token=//' | head -1)"
  [ -n "$TOKEN" ] && break
  sleep 1
done
test -n "$TOKEN"
curl --fail --silent -X POST "$BASE_URL/api/console/auth/verify-email" \
  -H 'Content-Type: application/json' -d "{\"token\":\"$TOKEN\"}" >/dev/null

echo "Console login"
curl --fail --silent -c /tmp/authplatform-smoke.cookies -X POST "$BASE_URL/api/console/auth/login" \
  -H 'Content-Type: application/json' -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" | jq -e '.account.email' >/dev/null

echo "Protected request with HttpOnly access cookie"
curl --fail --silent -b /tmp/authplatform-smoke.cookies "$BASE_URL/api/console/me" | jq -e '.email == "'"$EMAIL"'"' >/dev/null

echo "Smoke test passed"
