#!/bin/bash

# Auth Platform - Development server startup script

set -e

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default ports
BACKEND_PORT=8000
ADMIN_CONSOLE_PORT=3000
SAMPLE_APP_PORT=3001

# Function to display usage
usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  all          Start all services (backend, admin-console, sample-app)"
    echo "  backend      Start only the backend API server"
    echo "  admin        Start only the admin console frontend"
    echo "  sample-app   Start only the sample application"
    echo "  stop         Stop all running services"
    echo "  help         Show this help message"
    echo ""
    echo "Ports:"
    echo "  Backend API:     http://localhost:$BACKEND_PORT"
    echo "  Admin Console:   http://localhost:$ADMIN_CONSOLE_PORT"
    echo "  Sample App:      http://localhost:$SAMPLE_APP_PORT"
}

# Activate virtual environment if it exists
activate_venv() {
    if [ -d "$SCRIPT_DIR/.venv" ]; then
        source "$SCRIPT_DIR/.venv/bin/activate"
    fi
}

# Load environment variables
load_env() {
    if [ -f "$SCRIPT_DIR/.env" ]; then
        export $(grep -v '^#' "$SCRIPT_DIR/.env" | xargs)
    fi
}

# Start backend API server
start_backend() {
    echo "🚀 Starting Auth Platform Backend API on port $BACKEND_PORT..."
    activate_venv
    load_env
    cd "$SCRIPT_DIR/backend"
    uvicorn app.main:app --reload --host 0.0.0.0 --port $BACKEND_PORT &
    echo $! > "$SCRIPT_DIR/.backend.pid"
    echo "   Backend API running at http://localhost:$BACKEND_PORT"
}

# Start admin console
start_admin() {
    echo "🖥️  Starting Admin Console on port $ADMIN_CONSOLE_PORT..."
    cd "$SCRIPT_DIR/frontend/admin-console"
    python3 -m http.server $ADMIN_CONSOLE_PORT &
    echo $! > "$SCRIPT_DIR/.admin.pid"
    echo "   Admin Console running at http://localhost:$ADMIN_CONSOLE_PORT"
}

# Start sample app
start_sample_app() {
    echo "📱 Starting Sample App on port $SAMPLE_APP_PORT..."
    cd "$SCRIPT_DIR/sample-app"
    python3 -m http.server $SAMPLE_APP_PORT &
    echo $! > "$SCRIPT_DIR/.sample-app.pid"
    echo "   Sample App running at http://localhost:$SAMPLE_APP_PORT"
}

# Stop all services
stop_services() {
    echo "Stopping all services..."
    
    if [ -f "$SCRIPT_DIR/.backend.pid" ]; then
        kill $(cat "$SCRIPT_DIR/.backend.pid") 2>/dev/null || true
        rm "$SCRIPT_DIR/.backend.pid"
        echo "   Backend stopped"
    fi
    
    if [ -f "$SCRIPT_DIR/.admin.pid" ]; then
        kill $(cat "$SCRIPT_DIR/.admin.pid") 2>/dev/null || true
        rm "$SCRIPT_DIR/.admin.pid"
        echo "   Admin Console stopped"
    fi
    
    if [ -f "$SCRIPT_DIR/.sample-app.pid" ]; then
        kill $(cat "$SCRIPT_DIR/.sample-app.pid") 2>/dev/null || true
        rm "$SCRIPT_DIR/.sample-app.pid"
        echo "   Sample App stopped"
    fi
    
    # Also kill any orphaned processes
    pkill -f "uvicorn app.main:app" 2>/dev/null || true
    pkill -f "python3 -m http.server $ADMIN_CONSOLE_PORT" 2>/dev/null || true
    pkill -f "python3 -m http.server $SAMPLE_APP_PORT" 2>/dev/null || true
    
    echo "All services stopped"
}

# Start all services
start_all() {
    echo "============================================"
    echo "      Auth Platform - Starting Services    "
    echo "============================================"
    echo ""
    
    # Stop any existing services first
    stop_services 2>/dev/null || true
    
    start_backend
    sleep 2
    start_admin
    start_sample_app
    
    echo ""
    echo "============================================"
    echo "      All services started successfully!   "
    echo "============================================"
    echo ""
    echo "📍 Service URLs:"
    echo "   Backend API:    http://localhost:$BACKEND_PORT"
    echo "   Admin Console:  http://localhost:$ADMIN_CONSOLE_PORT"
    echo "   Sample App:     http://localhost:$SAMPLE_APP_PORT"
    echo ""
    echo "📖 API Docs:       http://localhost:$BACKEND_PORT/docs"
    echo ""
    echo "Press Ctrl+C to stop all services..."
    
    # Wait for user interrupt
    trap "stop_services; exit 0" INT TERM
    wait
}

# Main command handler
case "${1:-all}" in
    all)
        start_all
        ;;
    backend)
        activate_venv
        load_env
        start_backend
        wait
        ;;
    admin)
        start_admin
        wait
        ;;
    sample-app)
        start_sample_app
        wait
        ;;
    stop)
        stop_services
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