#!/bin/bash

# ============================================================
#  Auth Platform — Service Runner
# ============================================================

# NOTE: intentionally NO "set -e" — we do our own error handling
#       so one failed sub-command never kills the whole script.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ports
BACKEND_PORT=8000

# Temp files used to pass cloudflare URLs between functions
CF_BACKEND_URL_FILE="/tmp/.cf_backend_url"

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
    echo "    stop         Stop all running services"
    echo "    status       Show running service status"
    echo "    help         Show this help message"
    echo ""
    echo "  Service URLs:"
    echo "    Backend API      http://localhost:$BACKEND_PORT"
    echo "    API Docs         http://localhost:$BACKEND_PORT/docs"
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

free_port() {
    local port="$1"
    local pids
    pids=$(lsof -ti tcp:"$port" 2>/dev/null | sort -u || true)
    if [ -n "$pids" ]; then
        echo "[*] Port $port in use. Stopping process(es): $pids"
        kill $pids 2>/dev/null || true
        sleep 1

        # Hard kill only if still alive
        local remaining
        remaining=$(lsof -ti tcp:"$port" 2>/dev/null | sort -u || true)
        if [ -n "$remaining" ]; then
            kill -9 $remaining 2>/dev/null || true
            sleep 1
        fi
    fi
}

# -------------------- Cloudflare Tunnel --------------------

# start_cloudflare_tunnel <port> <label> <pidfile> <url_outfile>
#   Spawns cloudflared, polls its combined log for the public URL,
#   and writes that URL to <url_outfile> (plain temp file — no bash namerefs
#   which require bash 4.3+ and crash on macOS default bash 3.x).
start_cloudflare_tunnel() {
    local port="$1"
    local label="$2"
    local pidfile="$3"
    local url_outfile="$4"

    local logfile="/tmp/cf_tunnel_${label}.log"
    rm -f "$logfile" "$url_outfile"

    echo "[*] Starting Cloudflare tunnel for $label (port $port) ..."

    # cloudflared writes the URL to stderr — redirect both streams to logfile
    cloudflared tunnel --url "http://localhost:$port" --no-autoupdate \
        > "$logfile" 2>&1 &
    local pid=$!
    echo "$pid" > "$pidfile"

    # Poll up to 30 s for the trycloudflare URL
    local waited=0
    local found_url=""
    while [ "$waited" -lt 30 ]; do
        found_url=$(grep -o 'https://[a-zA-Z0-9-]*\.trycloudflare\.com' "$logfile" 2>/dev/null | head -1 || true)
        if [ -n "$found_url" ]; then
            echo "$found_url" > "$url_outfile"
            echo "    -> $found_url  [$label tunnel ready]"
            break
        fi
        sleep 1
        waited=$((waited + 1))   # plain arithmetic — safe with or without set -e
    done

    if [ -z "$found_url" ]; then
        echo "[!] Cloudflare URL not found for $label after 30s."
        echo "    Check log: $logfile"
        echo "" > "$url_outfile"
    fi
}

# -------------------- Service Control --------------------

start_backend() {
    echo "[*] Starting Backend API on port $BACKEND_PORT ..."
    free_port "$BACKEND_PORT"
    activate_venv
    load_env
    cd "$SCRIPT_DIR/backend"
    uvicorn app.main:app --reload --host 0.0.0.0 --port $BACKEND_PORT &
    local pid=$!
    sleep 1
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "[!] Backend failed to start on port $BACKEND_PORT"
        return 1
    fi
    echo "$pid" > "$SCRIPT_DIR/.backend.pid"
    echo "    -> http://localhost:$BACKEND_PORT"
    echo "    -> http://localhost:$BACKEND_PORT/docs  (Swagger)"
}

# Production backend: Gunicorn + UvicornWorker (replaces uvicorn dev server)
start_backend_prod() {
    echo "[*] Starting Backend API (Gunicorn + Uvicorn) on port $BACKEND_PORT ..."
    free_port "$BACKEND_PORT"
    activate_venv
    load_env
    cd "$SCRIPT_DIR/backend"

    # macOS blocks Objective-C runtime calls after fork() by default.
    # Gunicorn's pre-fork worker model triggers this — setting this env var disables the guard.
    export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES

    gunicorn app.main:app \
        --worker-class uvicorn.workers.UvicornWorker \
        --workers "${GUNICORN_WORKERS:-2}" \
        --bind "0.0.0.0:$BACKEND_PORT" \
        --log-level info \
        --access-logfile "/tmp/gunicorn_access.log" \
        --error-logfile  "/tmp/gunicorn_error.log" &
    local pid=$!
    sleep 3
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "[!] Gunicorn failed to start. Check /tmp/gunicorn_error.log"
        return 1
    fi
    echo "$pid" > "$SCRIPT_DIR/.backend.pid"
    echo "    -> http://localhost:$BACKEND_PORT  (Gunicorn + Uvicorn)"
    echo "    -> Logs: /tmp/gunicorn_access.log | /tmp/gunicorn_error.log"
}


stop_services() {
    echo "[*] Stopping services ..."

    for svc in backend cf_backend; do
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
    pkill -f "uvicorn app.main:app"  2>/dev/null || true
    pkill -f "gunicorn app.main:app" 2>/dev/null || true
    pkill -f "cloudflared tunnel"    2>/dev/null || true

    # Clean up temp URL files
    rm -f "$CF_BACKEND_URL_FILE"

    echo "[*] All services stopped."
}

show_status() {
    echo ""
    echo "  Service Status"
    echo "  ────────────────────────────────────────"

    for svc in backend cf_backend; do
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

    # ---- Prompt: new deployment server? ----
    local deploy_mode="no"
    read -r -p "  Is this a new deployment server? [y/N]: " deploy_answer
    case "$deploy_answer" in
        [Yy]|[Yy][Ee][Ss]) deploy_mode="yes" ;;
        *) deploy_mode="no" ;;
    esac
    echo ""

    # Stop any existing services first
    stop_services 2>/dev/null || true
    echo ""

    if [ "$deploy_mode" = "yes" ]; then
        # ---- Production mode: Gunicorn + Uvicorn + Cloudflare ----
        echo "  [Deployment Mode] Using Gunicorn + Cloudflare tunnels"
        echo ""

        start_backend_prod
        sleep 2

        # Start Cloudflare tunnels — URLs written to temp files (not namerefs)
        start_cloudflare_tunnel \
            "$BACKEND_PORT"       "backend" \
            "$SCRIPT_DIR/.cf_backend.pid" "$CF_BACKEND_URL_FILE"


        # Read URLs from temp files
        local backend_url
        backend_url=$(cat "$CF_BACKEND_URL_FILE" 2>/dev/null || true)

        echo ""
        echo "  ============================================"
        echo "   All services running  [Deployment Mode]"
        echo "  ============================================"
        echo ""
        echo "  Local"
        echo "    Backend API    http://localhost:$BACKEND_PORT"
        echo "    API Docs       http://localhost:$BACKEND_PORT/docs"
        echo ""
        echo "  Public (Cloudflare)"
        echo "    Server URL   ${backend_url:-<not ready — check /tmp/cf_tunnel_backend.log>}"
        echo ""
        echo ""

    else
        # ---- Dev mode (original behaviour) ----
        start_backend
        sleep 2

        echo ""
        echo "  ============================================"
        echo "   All services running."
        echo "  ============================================"
        echo ""
        echo "  Backend API      http://localhost:$BACKEND_PORT"
        echo "  API Docs         http://localhost:$BACKEND_PORT/docs"
              echo ""
    fi

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