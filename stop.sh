#!/bin/bash

# NexusTrace Stop Script
# Handles graceful shutdown and cleanup
# Usage:
#   ./stop.sh           - Stop development server
#   ./stop.sh --docker  - Stop Docker containers
#   ./stop.sh --all     - Stop both dev server and Docker
#   ./stop.sh --clean   - Stop and clean cache files
#   ./stop.sh --status  - Show running status

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

show_help() {
    echo "NexusTrace Stop Script"
    echo ""
    echo "Usage: ./stop.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  (none)      Stop development server"
    echo "  --docker    Stop Docker containers"
    echo "  --all       Stop both dev server and Docker containers"
    echo "  --clean     Stop and clean Python cache files"
    echo "  --status    Show what's currently running"
    echo "  --help      Show this help message"
}

stop_dev_server() {
    local stopped=false
    PID_FILE=".nexustrace.pid"

    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            log_step "Stopping dev server (PID: $PID)..."
            kill "$PID" 2>/dev/null
            sleep 2

            # Force kill if still running
            if ps -p "$PID" > /dev/null 2>&1; then
                log_warn "Process didn't stop gracefully, forcing..."
                kill -9 "$PID" 2>/dev/null
            fi
            stopped=true
        fi
        rm -f "$PID_FILE"
    fi

    # Also check for any process on port 5050 (non-Docker)
    if lsof -ti:5050 > /dev/null 2>&1; then
        # Check if it's not a Docker process
        if ! docker ps 2>/dev/null | grep -q ":5050"; then
            log_step "Stopping process on port 5050..."
            lsof -ti:5050 | xargs kill -9 2>/dev/null || true
            stopped=true
        fi
    fi

    if [ "$stopped" = true ]; then
        log_info "Development server stopped"
    else
        log_info "No development server running"
    fi
}

stop_docker() {
    # Check if docker-compose is available
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null 2>&1; then
        log_warn "docker-compose not found"
        return
    fi

    # Determine docker compose command
    if docker compose version &> /dev/null 2>&1; then
        COMPOSE="docker compose"
    else
        COMPOSE="docker-compose"
    fi

    if docker ps 2>/dev/null | grep -q "nexustrace"; then
        log_step "Stopping Docker containers..."
        $COMPOSE down
        log_info "Docker containers stopped"
    else
        log_info "No Docker containers running"
    fi
}

clean_cache() {
    log_step "Cleaning Python cache files..."
    find . -type d -name "__pycache__" -not -path "./venv/*" -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name "*.pyc" -not -path "./venv/*" -delete 2>/dev/null || true
    find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
    log_info "Cache cleaned"
}

show_status() {
    echo ""
    echo "=== NexusTrace Status ==="
    echo ""

    # Check dev server
    PID_FILE=".nexustrace.pid"
    if [ -f "$PID_FILE" ] && ps -p "$(cat "$PID_FILE")" > /dev/null 2>&1; then
        echo -e "${GREEN}[RUNNING]${NC} Development server (PID: $(cat "$PID_FILE"))"
    elif lsof -ti:5050 > /dev/null 2>&1 && ! docker ps 2>/dev/null | grep -q ":5050"; then
        echo -e "${GREEN}[RUNNING]${NC} Process on port 5050"
    else
        echo -e "${YELLOW}[STOPPED]${NC} Development server"
    fi

    # Check Docker
    if docker ps 2>/dev/null | grep -q "nexustrace_web"; then
        echo -e "${GREEN}[RUNNING]${NC} Docker web container"
    else
        echo -e "${YELLOW}[STOPPED]${NC} Docker web container"
    fi

    if docker ps 2>/dev/null | grep -q "nexustrace_nginx"; then
        echo -e "${GREEN}[RUNNING]${NC} Docker nginx container"
    else
        echo -e "${YELLOW}[STOPPED]${NC} Docker nginx container"
    fi

    echo ""

    # Show ports in use
    if lsof -i:5050 > /dev/null 2>&1; then
        echo "Port 5050: IN USE"
    fi
    if lsof -i:80 > /dev/null 2>&1; then
        echo "Port 80: IN USE"
    fi
}

# Parse arguments
case "${1:-}" in
    --docker)
        stop_docker
        ;;
    --all)
        stop_dev_server
        stop_docker
        ;;
    --clean)
        stop_dev_server
        clean_cache
        ;;
    --status)
        show_status
        ;;
    --help|-h)
        show_help
        ;;
    "")
        stop_dev_server
        ;;
    *)
        log_error "Unknown option: $1"
        show_help
        exit 1
        ;;
esac
