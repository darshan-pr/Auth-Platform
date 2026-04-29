#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/run-docker.sh"

usage() {
    echo ""
    echo "Usage: ./scripts/docker-fresh.sh [command]"
    echo ""
    echo "Commands:"
    echo "  stop    Stop running Docker services for this stack"
    echo "  clean   Stop services and remove volumes/data"
    echo "  nuke    Full reset: remove containers, images, volumes, build cache"
    echo ""
}

cmd="${1:-stop}"

case "$cmd" in
    stop)
        "$RUNNER" stop
        ;;
    clean)
        "$RUNNER" clean
        ;;
    nuke|fresh|reset)
        "$RUNNER" nuke
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        echo "Unknown command: $cmd"
        usage
        exit 1
        ;;
esac
