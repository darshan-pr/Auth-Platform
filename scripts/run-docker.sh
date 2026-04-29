#!/bin/bash

# ============================================================
#  Auth Platform — Production Docker Runner
# ============================================================
#
#  Runs the entire auth platform in Docker with:
#    • PostgreSQL 16       — database
#    • Redis 7             — sessions, cache, rate limiting
#    • Gunicorn + Uvicorn  — ASGI application server
#    • Nginx               — reverse proxy, gzip, rate limiting
#    • Cloudflare Tunnel   — public HTTPS endpoint
#
#  Usage:
#    ./scripts/run-docker.sh start        Start all services (build + up)
#    ./scripts/run-docker.sh stop         Stop all services
#    ./scripts/run-docker.sh restart      Restart all services
#    ./scripts/run-docker.sh status       Show service health
#    ./scripts/run-docker.sh logs         Tail live logs
#    ./scripts/run-docker.sh logs <svc>   Tail logs for one service
#    ./scripts/run-docker.sh tunnel-url   Print the Cloudflare tunnel URL
#    ./scripts/run-docker.sh shell        Open shell in backend container
#    ./scripts/run-docker.sh psql         Open PostgreSQL CLI
#    ./scripts/run-docker.sh redis-cli    Open Redis CLI
#    ./scripts/run-docker.sh rebuild      Force rebuild and restart
#    ./scripts/run-docker.sh clean        Stop + remove volumes (DESTRUCTIVE)
#    ./scripts/run-docker.sh nuke         Stop + remove images/volumes/cache
#    ./scripts/run-docker.sh help         Show this help
#
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/docker-compose.prod.yml"
DEV_COMPOSE_FILE="$ROOT_DIR/docker-compose.yml"
PROJECT_NAME="auth-platform-prod"
RUN_CMD="./scripts/run-docker.sh"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ── Helpers ──

print_banner() {
    echo ""
    echo -e "${CYAN}${BOLD}"
    echo "  ╔═══════════════════════════════════════════════════╗"
    echo "  ║       Auth Platform — Production Docker           ║"
    echo "  ╚═══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

info()    { echo -e "  ${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "  ${GREEN}[  OK]${NC}  $*"; }
warn()    { echo -e "  ${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "  ${RED}[FAIL]${NC}  $*"; }

dc() {
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" "$@"
}

check_docker() {
    if ! command -v docker &>/dev/null; then
        error "Docker is not installed. Please install Docker Desktop first."
        echo "       https://docs.docker.com/desktop/install/mac-install/"
        exit 1
    fi

    if ! docker info &>/dev/null; then
        error "Docker daemon is not running. Please start Docker Desktop."
        exit 1
    fi
}

check_env() {
    local env_file="$ROOT_DIR/.env"

    if [ ! -f "$env_file" ]; then
        warn "No .env file found. Copying from .env.example ..."
        if [ -f "$ROOT_DIR/.env.example" ]; then
            cp "$ROOT_DIR/.env.example" "$env_file"
            warn "Please edit .env with your actual credentials before proceeding."
            exit 1
        else
            error "No .env or .env.example found. Create .env with required variables."
            exit 1
        fi
    fi

    # Source .env for variable interpolation in this script
    set -a
    source "$env_file"
    set +a
}

wait_for_healthy() {
    local service="$1"
    local timeout="${2:-120}"
    local elapsed=0

    while [ $elapsed -lt $timeout ]; do
        local health
        health=$(docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" \
                 ps --format json "$service" 2>/dev/null \
                 | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('Health',''))" 2>/dev/null || echo "")

        if [ "$health" = "healthy" ]; then
            return 0
        fi

        sleep 2
        elapsed=$((elapsed + 2))
    done

    return 1
}

get_tunnel_url() {
    local service="${1:-cloudflared}"
    local url
    url=$(dc logs "$service" 2>&1 \
          | grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' \
          | tail -1 || true)
    echo "$url"
}

wait_for_tunnel() {
    local service="${1:-cloudflared}"
    local label="${2:-backend}"
    local timeout=60
    local elapsed=0
    local url=""

    info "Waiting for Cloudflare tunnel ($label) to establish ..."

    while [ $elapsed -lt $timeout ]; do
        url=$(get_tunnel_url "$service")
        if [ -n "$url" ]; then
            echo "$url"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done

    echo ""
    return 1
}

# ── Commands ──

cmd_start() {
    print_banner
    check_docker
    check_env

    info "Building and starting all services ..."
    echo ""

    # Step 1: Build images
    info "Building Docker images ..."
    dc build --parallel 2>&1 | sed 's/^/       /'
    success "Images built"
    echo ""

    # Step 2: Run database migrations (one-shot container)
    info "Running database migrations ..."
    dc run --rm migrations 2>&1 | sed 's/^/       /'
    local rc=${PIPESTATUS[0]:-0}
    if [ "$rc" -ne 0 ]; then
        error "Migration failed. Check logs with: $RUN_CMD logs migrations"
        exit 1
    fi
    success "Migrations complete"
    echo ""

    # Step 3: Start all services
    info "Starting services ..."
    dc up -d postgres redis backend nginx cloudflared frontend cloudflared-frontend
    echo ""

    # Step 4: Wait for health checks
    info "Waiting for services to become healthy ..."

    for svc in postgres redis backend nginx frontend; do
        if wait_for_healthy "$svc" 90; then
            success "$svc is healthy"
        else
            warn "$svc failed health check. Run: $RUN_CMD logs $svc"
        fi
    done
    echo ""

    # Step 5: Get Cloudflare tunnel URLs
    local backend_tunnel_url
    backend_tunnel_url=$(wait_for_tunnel "cloudflared" "backend")

    local frontend_tunnel_url
    frontend_tunnel_url=$(wait_for_tunnel "cloudflared-frontend" "frontend")

    # Step 6: Print summary
    echo ""
    echo -e "  ${GREEN}${BOLD}╔═══════════════════════════════════════════════════╗${NC}"
    echo -e "  ${GREEN}${BOLD}║          All services running                     ║${NC}"
    echo -e "  ${GREEN}${BOLD}╚═══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Local Access${NC}"
    echo -e "    Backend (Nginx)   ${CYAN}http://localhost:${NGINX_PORT:-8000}${NC}"
    echo -e "    Frontend          ${CYAN}http://localhost:3000${NC}"
    echo -e "    API Docs          ${CYAN}http://localhost:${NGINX_PORT:-8000}/docs${NC}"
    echo -e "    Landing Page      ${CYAN}http://localhost:${NGINX_PORT:-8000}/${NC}"
    echo ""
    echo -e "  ${BOLD}Public Access (Cloudflare Tunnels)${NC}"
    if [ -n "$backend_tunnel_url" ]; then
        echo -e "    Backend (API)     ${GREEN}${BOLD}$backend_tunnel_url${NC}"
    else
        echo -e "    Backend (API)     ${YELLOW}Not ready. Check: $RUN_CMD logs cloudflared${NC}"
    fi
    if [ -n "$frontend_tunnel_url" ]; then
        echo -e "    Frontend (App)    ${GREEN}${BOLD}$frontend_tunnel_url${NC}"
    else
        echo -e "    Frontend (App)    ${YELLOW}Not ready. Check: $RUN_CMD logs cloudflared-frontend${NC}"
    fi
    echo ""
    if [ -n "$backend_tunnel_url" ]; then
        echo -e "  ${YELLOW}[TIP]${NC}  Update .env with tunnel URLs:"
        echo -e "         AUTH_SERVER_URL=$backend_tunnel_url"
        echo -e "         AUTH_PLATFORM_URL=$backend_tunnel_url"
        if [ -n "$frontend_tunnel_url" ]; then
            echo -e "         ALLOWED_ORIGINS=...,${backend_tunnel_url},${frontend_tunnel_url}"
        fi
        echo -e "         Then run: ${BOLD}$RUN_CMD restart${NC}"
    fi
    echo ""
    echo -e "  ${BOLD}Architecture${NC}"
    echo -e "    Internet → Cloudflare → Nginx:80 → Gunicorn:8000 → PostgreSQL + Redis"
    echo -e "    Internet → Cloudflare → Next.js:3000 (frontend demo app)"
    echo ""
    echo -e "  ${BOLD}Commands${NC}"
    echo -e "    $RUN_CMD logs         Tail all logs"
    echo -e "    $RUN_CMD status       Check service health"
    echo -e "    $RUN_CMD stop         Stop everything"
    echo -e "    $RUN_CMD tunnel-url   Get public URLs"
    echo ""
}

cmd_stop() {
    print_banner
    check_docker

    info "Stopping all services ..."
    dc down
    success "All services stopped"
    echo ""
}

cmd_restart() {
    print_banner
    check_docker
    check_env

    info "Restarting all services ..."
    dc down
    cmd_start
}

cmd_rebuild() {
    print_banner
    check_docker
    check_env

    info "Rebuilding all images from scratch ..."
    dc down
    dc build --no-cache --parallel 2>&1 | sed 's/^/       /'
    success "Rebuild complete"
    echo ""
    cmd_start
}

cmd_status() {
    print_banner
    check_docker

    echo -e "  ${BOLD}Service Status${NC}"
    echo "  ─────────────────────────────────────────"
    echo ""

    dc ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || dc ps
    echo ""

    local backend_url
    backend_url=$(get_tunnel_url "cloudflared")
    local frontend_url
    frontend_url=$(get_tunnel_url "cloudflared-frontend")

    echo -e "  ${BOLD}Cloudflare Tunnels${NC}"
    if [ -n "$backend_url" ]; then
        echo -e "    Backend:  ${GREEN}$backend_url${NC}"
    else
        echo -e "    Backend:  ${YELLOW}Not ready or not running${NC}"
    fi
    if [ -n "$frontend_url" ]; then
        echo -e "    Frontend: ${GREEN}$frontend_url${NC}"
    else
        echo -e "    Frontend: ${YELLOW}Not ready or not running${NC}"
    fi
    echo ""
}

cmd_logs() {
    check_docker
    local service="${1:-}"

    if [ -n "$service" ]; then
        dc logs -f --tail=100 "$service"
    else
        dc logs -f --tail=50
    fi
}

cmd_tunnel_url() {
    check_docker

    local backend_url
    backend_url=$(get_tunnel_url "cloudflared")
    local frontend_url
    frontend_url=$(get_tunnel_url "cloudflared-frontend")

    echo ""
    if [ -n "$backend_url" ]; then
        echo -e "  Backend:  ${GREEN}$backend_url${NC}"
    else
        echo -e "  Backend:  ${YELLOW}Not found${NC}"
    fi
    if [ -n "$frontend_url" ]; then
        echo -e "  Frontend: ${GREEN}$frontend_url${NC}"
    else
        echo -e "  Frontend: ${YELLOW}Not found${NC}"
    fi
    echo ""

    if [ -z "$backend_url" ] && [ -z "$frontend_url" ]; then
        error "No tunnels found. Are cloudflared containers running?"
        echo "  Check with: $RUN_CMD logs cloudflared"
        exit 1
    fi
}

cmd_shell() {
    check_docker
    info "Opening shell in backend container ..."
    dc exec backend /bin/bash
}

cmd_psql() {
    check_docker
    info "Opening PostgreSQL CLI ..."
    dc exec postgres psql -U auth_admin -d auth_db
}

cmd_redis_cli() {
    check_docker
    info "Opening Redis CLI ..."
    dc exec redis redis-cli
}

cmd_clean() {
    print_banner
    check_docker

    echo ""
    echo -e "  ${RED}${BOLD}WARNING: This will delete ALL data (database, Redis, JWT keys)${NC}"
    echo ""
    read -r -p "  Are you sure? Type 'yes' to confirm: " confirm
    echo ""

    if [ "$confirm" != "yes" ]; then
        info "Cancelled."
        exit 0
    fi

    info "Stopping services and removing volumes ..."
    dc down -v
    success "All services stopped and volumes removed"
    echo ""
}

cmd_nuke() {
    print_banner
    check_docker

    echo ""
    echo -e "  ${RED}${BOLD}WARNING: This will fully reset Auth Platform Docker resources${NC}"
    echo -e "  ${RED}It removes containers, images, volumes, networks, and build cache for this stack.${NC}"
    echo ""
    read -r -p "  Type 'NUKE' to confirm full cleanup: " confirm
    echo ""

    if [ "$confirm" != "NUKE" ]; then
        info "Cancelled."
        exit 0
    fi

    info "Stopping/removing production stack (containers, images, volumes) ..."
    dc down --volumes --remove-orphans --rmi all || true

    if [ -f "$DEV_COMPOSE_FILE" ]; then
        info "Stopping/removing local compose stack if present ..."
        docker compose -f "$DEV_COMPOSE_FILE" down --volumes --remove-orphans --rmi all || true
    fi

    info "Removing leftover auth-platform images ..."
    local image_ids
    image_ids=$(docker images --format '{{.Repository}} {{.ID}}' \
        | awk '$1 ~ /^auth-platform/ {print $2}' \
        | sort -u)
    if [ -n "$image_ids" ]; then
        while IFS= read -r image_id; do
            [ -n "$image_id" ] && docker rmi -f "$image_id" >/dev/null 2>&1 || true
        done <<< "$image_ids"
    fi

    info "Pruning Docker build cache ..."
    docker builder prune -af >/dev/null 2>&1 || true

    success "Docker resources removed. Fresh state ready."
    echo ""
}

cmd_help() {
    print_banner
    echo -e "  ${BOLD}Usage:${NC} $RUN_CMD [command]"
    echo ""
    echo -e "  ${BOLD}Commands:${NC}"
    echo "    start          Build and start all services (default)"
    echo "    stop           Stop all services"
    echo "    restart        Stop + start"
    echo "    rebuild        Force rebuild images from scratch"
    echo "    status         Show service health and URLs"
    echo "    logs [svc]     Tail logs (optionally for one service)"
    echo "    tunnel-url     Print the current Cloudflare tunnel URL"
    echo "    shell          Open bash in the backend container"
    echo "    psql           Open PostgreSQL CLI"
    echo "    redis-cli      Open Redis CLI"
    echo "    clean          Stop + delete all data (DESTRUCTIVE)"
    echo "    nuke           Full reset (containers + images + volumes + cache)"
    echo "    help           Show this help"
    echo ""
    echo -e "  ${BOLD}Architecture:${NC}"
    echo "    Internet → Cloudflare Tunnel → Nginx (rate limiting, gzip, headers)"
    echo "             → Gunicorn + Uvicorn Workers → PostgreSQL + Redis"
    echo ""
    echo -e "  ${BOLD}Services:${NC}"
    echo "    postgres       PostgreSQL 16 (database)"
    echo "    redis          Redis 7 (sessions, cache, rate limiting)"
    echo "    backend        Gunicorn + Uvicorn (Python ASGI app)"
    echo "    nginx          Nginx reverse proxy (security, caching)"
    echo "    cloudflared    Cloudflare Tunnel (public HTTPS)"
    echo ""
    echo -e "  ${BOLD}Examples:${NC}"
    echo "    $RUN_CMD start              # First-time setup"
    echo "    $RUN_CMD logs backend       # Debug backend issues"
    echo "    $RUN_CMD tunnel-url         # Get public URL"
    echo "    $RUN_CMD psql               # Run SQL queries"
    echo "    $RUN_CMD nuke               # Full cleanup for a fresh Docker state"
    echo ""
}

# ── Main ──

case "${1:-start}" in
    start)      cmd_start ;;
    stop)       cmd_stop ;;
    restart)    cmd_restart ;;
    rebuild)    cmd_rebuild ;;
    status)     cmd_status ;;
    logs)       cmd_logs "${2:-}" ;;
    tunnel-url) cmd_tunnel_url ;;
    shell)      cmd_shell ;;
    psql)       cmd_psql ;;
    redis-cli)  cmd_redis_cli ;;
    clean)      cmd_clean ;;
    nuke)       cmd_nuke ;;
    help|--help|-h)  cmd_help ;;
    *)
        error "Unknown command: $1"
        cmd_help
        exit 1
        ;;
esac
