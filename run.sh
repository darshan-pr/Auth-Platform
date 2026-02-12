#!/bin/bash

# ============================================================
#  Auth Platform — Service Runner
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ports
BACKEND_PORT=8000
ADMIN_CONSOLE_PORT=3000

# -------------------- Helpers --------------------

usage() {
    echo ""
    echo "  Auth Platform — Service Runner"
    echo "  ────────────────────────────────────────"
    echo ""
    echo "  Usage: ./run.sh [command]"
    echo ""
    echo "  Commands:"
    echo "    start        Start all services (default)"
    echo "    backend      Start only the backend API"
    echo "    admin        Start only the admin console"
    echo "    stop         Stop all running services"
    echo "    status       Show running service status"
    echo "    help         Show this help message"
    echo ""
    echo "  Service URLs:"
    echo "    Backend API      http://localhost:$BACKEND_PORT"
    echo "    API Docs         http://localhost:$BACKEND_PORT/docs"
    echo "    Admin Console    http://localhost:$ADMIN_CONSOLE_PORT"
    echo ""
}

activate_venv() {
    if [ -d "$SCRIPT_DIR/.venv" ]; then
        source "$SCRIPT_DIR/.venv/bin/activate"
    elif [ -d "$SCRIPT_DIR/backend/.venv" ]; then
        source "$SCRIPT_DIR/backend/.venv/bin/activate"
    elif [ -d "$SCRIPT_DIR/backend/venv" ]; then
        source "$SCRIPT_DIR/backend/venv/bin/activate"
    fi
}

load_env() {
    if [ -f "$SCRIPT_DIR/.env" ]; then
        set -a
        source "$SCRIPT_DIR/.env"
        set +a
    fi
}

# -------------------- Service Control --------------------

start_backend() {
    echo "[*] Starting Backend API on port $BACKEND_PORT ..."
    activate_venv
    load_env
    cd "$SCRIPT_DIR/backend"
    uvicorn app.main:app --reload --host 0.0.0.0 --port $BACKEND_PORT &
    echo $! > "$SCRIPT_DIR/.backend.pid"
    echo "    -> http://localhost:$BACKEND_PORT"
    echo "    -> http://localhost:$BACKEND_PORT/docs  (Swagger)"
}

start_admin() {
    echo "[*] Starting Admin Console on port $ADMIN_CONSOLE_PORT ..."
    cd "$SCRIPT_DIR/frontend/admin-console"
    python3 -m http.server $ADMIN_CONSOLE_PORT &
    echo $! > "$SCRIPT_DIR/.admin.pid"
    echo "    -> http://localhost:$ADMIN_CONSOLE_PORT"
}

stop_services() {
    echo "[*] Stopping services ..."

    for svc in backend admin; do
        pidfile="$SCRIPT_DIR/.${svc}.pid"
        if [ -f "$pidfile" ]; then
            pid=$(cat "$pidfile")
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
                echo "    $svc stopped  (pid $pid)"
            fi
            rm -f "$pidfile"
        fi
    done

    # Clean up orphans
    pkill -f "uvicorn app.main:app" 2>/dev/null || true
    pkill -f "python3 -m http.server $ADMIN_CONSOLE_PORT" 2>/dev/null || true

    echo "[*] All services stopped."
}

show_status() {
    echo ""
    echo "  Service Status"
    echo "  ────────────────────────────────────────"

    for svc in backend admin; do
        pidfile="$SCRIPT_DIR/.${svc}.pid"
        if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
            echo "    $svc : running  (pid $(cat "$pidfile"))"
        else
            echo "    $svc : stopped"
        fi
    done

    echo ""
}

start_all() {
    echo ""
    echo "  ============================================"
    echo "   Auth Platform — Starting Services"
    echo "  ============================================"
    echo ""

    # Stop any existing services first
    stop_services 2>/dev/null || true
    echo ""

    start_backend
    sleep 2
    start_admin

    echo ""
    echo "  ============================================"
    echo "   All services running."
    echo "  ============================================"
    echo ""
    echo "  Backend API      http://localhost:$BACKEND_PORT"
    echo "  API Docs         http://localhost:$BACKEND_PORT/docs"
    echo "  Admin Console    http://localhost:$ADMIN_CONSOLE_PORT"
    echo ""
    echo "  Press Ctrl+C to stop all services ..."
    echo ""

    trap "stop_services; exit 0" INT TERM
    wait
}

# -------------------- Main --------------------

case "${1:-start}" in
    start|all)
        start_all
        ;;
    backend)
        activate_venv
        load_env
        start_backend
        echo ""
        echo "  Press Ctrl+C to stop ..."
        trap "stop_services; exit 0" INT TERM
        wait
        ;;
    admin)
        start_admin
        echo ""
        echo "  Press Ctrl+C to stop ..."
        trap "stop_services; exit 0" INT TERM
        wait
        ;;
    stop)
        stop_services
        ;;
    status)
        show_status
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        echo "Unknown command: $1"
        usage
        exit 1
        ;;
esac