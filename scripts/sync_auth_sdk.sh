#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${ROOT_DIR}/backend/app/static/auth-sdk.js"
DST="${ROOT_DIR}/next-app/lib/auth-sdk.js"
MODE="${1:-write}"

if [[ ! -f "${SRC}" ]]; then
  echo "Source SDK not found: ${SRC}" >&2
  exit 1
fi

TMP_FILE="$(mktemp)"
trap 'rm -f "${TMP_FILE}"' EXIT

awk '
/if \(typeof window !== '\''undefined'\''\) window\.AuthClient = AuthClient;/ { next }
{
  gsub(/Browser Global Export/, "Export for ES modules (Next.js \/ Vite \/ etc.)")
  print
}
END {
  print "export default AuthClient;"
}
' "${SRC}" > "${TMP_FILE}"

if [[ "${MODE}" == "check" ]]; then
  if cmp -s "${TMP_FILE}" "${DST}"; then
    echo "auth-sdk.js is in sync"
    exit 0
  fi
  echo "auth-sdk.js is out of sync" >&2
  exit 1
fi

cp "${TMP_FILE}" "${DST}"
echo "Synced ${DST} from ${SRC}"
