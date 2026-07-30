#!/bin/bash

# NexusTrace Start Script
# Handles dependency updates and server startup
# Usage:
#   ./start.sh          - Start development server
#   ./start.sh --docker - Start/rebuild Docker containers
#   ./start.sh --prod   - Production Docker deployment (cached build)
#   ./start.sh --clean  - Production deployment with a cold, no-cache rebuild

set -e

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
    echo "NexusTrace Start Script"
    echo ""
    echo "Usage: ./start.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  (none)      Start development server (background, logs to logs/nexustrace.log)"
    echo "  --docker    Start Docker containers (rebuild if code changed)"
    echo "  --prod      Production Docker deployment (cached build)"
    echo "  --clean     Production deployment, discarding the build cache"
    echo "  --logs      Tail the dev server log (logs/nexustrace.log)"
    echo "  --help      Show this help message"
    echo ""
    echo "Examples:"
    echo "  ./start.sh              # Dev server on port 5050"
    echo "  ./start.sh --docker     # Docker on ports 80 (nginx) & 5050"
    echo "  ./start.sh --prod       # Production, reusing cached layers (minutes)"
    echo "  ./start.sh --clean      # Only when you need a cold rebuild (~40 min:"
    echo "                          # re-downloads Chromium and all apt/pip deps)"
    echo "  ./start.sh --logs       # Follow server logs"
}

# Parse arguments
MODE="dev"
case "${1:-}" in
    --docker)
        MODE="docker"
        ;;
    --prod)
        MODE="prod"
        ;;
    --clean)
        MODE="clean"
        ;;
    --logs)
        if [ -f "logs/nexustrace.log" ]; then
            tail -f logs/nexustrace.log
        else
            log_warn "No log file found at logs/nexustrace.log"
            log_warn "Start the server first with: ./start.sh"
        fi
        exit 0
        ;;
    --help|-h)
        show_help
        exit 0
        ;;
    "")
        MODE="dev"
        ;;
    *)
        log_error "Unknown option: $1"
        show_help
        exit 1
        ;;
esac

# Check for .env file
if [ ! -f ".env" ]; then
    log_warn ".env file not found. Copy .env.example and configure your API keys."
fi

if [ "$MODE" = "docker" ] || [ "$MODE" = "prod" ] || [ "$MODE" = "clean" ]; then
    # Docker mode
    log_info "Starting NexusTrace in Docker mode..."

    # Check if docker-compose is available
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "docker-compose not found. Please install Docker Compose."
        exit 1
    fi

    # Determine docker compose command
    if docker compose version &> /dev/null 2>&1; then
        COMPOSE="docker compose"
    else
        COMPOSE="docker-compose"
    fi

    log_step "Stopping existing containers..."
    $COMPOSE down 2>/dev/null || true

    # --no-cache is opt-in via --clean, not the default for --prod. A cold build
    # re-downloads Chromium, every apt package, and every wheel; on the 2-core
    # production VM that is ~40 minutes, versus minutes for a cached build.
    if [ "$MODE" = "clean" ]; then
        log_warn "Cold rebuild: discarding the build cache. Expect ~40 minutes."
        $COMPOSE build --no-cache
    else
        log_step "Building containers (using cache)..."
        $COMPOSE build
    fi

    log_step "Starting containers..."
    $COMPOSE up -d

    log_info "Docker containers started!"
    log_info "  Web app: http://localhost:5050"
    log_info "  Nginx:   http://localhost:80"
    echo ""
    log_info "Use './stop.sh --docker' to stop containers"
    log_info "Use 'docker-compose logs -f' to view logs"

else
    # Development mode
    log_info "Starting NexusTrace in development mode..."

    # Warn if running as root
    if [ "$EUID" -eq 0 ]; then
        log_warn "Running as root is not recommended. Run without sudo."
    fi

    # Check if Docker containers are running on same ports
    if docker ps 2>/dev/null | grep -q "nexustrace"; then
        log_warn "Docker containers are running. Stop them first with './stop.sh --docker'"
        log_warn "Or they may conflict with the dev server."
    fi

    # Ensure uv is installed (manages the virtualenv + dependencies)
    if ! command -v uv &> /dev/null; then
        log_error "uv is not installed. Install it with:"
        log_error "  curl -LsSf https://astral.sh/uv/install.sh | sh"
        exit 1
    fi

    # Sync dependencies into .venv from uv.lock (creates the venv if missing; fast & cached)
    log_step "Syncing dependencies with uv..."
    uv sync

    # Use the uv-managed venv's Python directly (works even without activation)
    PYTHON="$SCRIPT_DIR/.venv/bin/python3"

    # Kill any existing NexusTrace process on port 5050
    if lsof -ti:5050 > /dev/null 2>&1; then
        log_warn "Port 5050 in use. Stopping existing process..."
        lsof -ti:5050 | xargs kill -9 2>/dev/null || true
        sleep 1
    fi

    # Ensure logs directory exists
    mkdir -p logs

    # Start the server
    log_step "Starting Flask development server..."
    echo ""

    # Save PID for stop script (use venv python), redirect output to log file
    "$PYTHON" main.py > logs/nexustrace.log 2>&1 &
    echo $! > .nexustrace.pid

    log_info "Server started with PID $(cat .nexustrace.pid)"
    log_info "Running at http://0.0.0.0:5050"
    log_info "Logs: logs/nexustrace.log  (./start.sh --logs to tail)"
    log_info "Use './stop.sh' to stop the server"

    # Wait for server to be ready
    sleep 2
    if curl -s http://localhost:5050/ > /dev/null 2>&1; then
        log_info "Server is ready!"
    else
        log_warn "Server may still be starting up. Check: ./start.sh --logs"
    fi
fi
