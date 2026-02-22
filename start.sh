#!/bin/bash

# NexusTrace Start Script
# Handles dependency updates and server startup
# Usage:
#   ./start.sh          - Start development server
#   ./start.sh --docker - Start/rebuild Docker containers
#   ./start.sh --prod   - Start production Docker with rebuild

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
    echo "  (none)      Start development server (Flask debug mode)"
    echo "  --docker    Start Docker containers (rebuild if code changed)"
    echo "  --prod      Production Docker deployment (full rebuild)"
    echo "  --help      Show this help message"
    echo ""
    echo "Examples:"
    echo "  ./start.sh              # Dev server on port 5050"
    echo "  ./start.sh --docker     # Docker on ports 80 (nginx) & 5050"
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

if [ "$MODE" = "docker" ] || [ "$MODE" = "prod" ]; then
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

    if [ "$MODE" = "prod" ]; then
        log_step "Building containers (full rebuild)..."
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

    # Check if virtual environment exists
    VENV_DIR="venv"
    if [ ! -d "$VENV_DIR" ]; then
        log_step "Creating virtual environment..."
        python3 -m venv "$VENV_DIR"
    fi

    # Use venv's Python and pip directly (works even without activation)
    PYTHON="$SCRIPT_DIR/$VENV_DIR/bin/python3"
    PIP="$SCRIPT_DIR/$VENV_DIR/bin/pip"

    # Update dependencies using venv pip
    log_step "Updating dependencies..."
    "$PIP" install -q --upgrade pip
    "$PIP" install -q -r requirements.txt

    # Kill any existing NexusTrace process on port 5050
    if lsof -ti:5050 > /dev/null 2>&1; then
        log_warn "Port 5050 in use. Stopping existing process..."
        lsof -ti:5050 | xargs kill -9 2>/dev/null || true
        sleep 1
    fi

    # Start the server
    log_step "Starting Flask development server..."
    echo ""

    # Save PID for stop script (use venv python)
    "$PYTHON" main.py &
    echo $! > .nexustrace.pid

    log_info "Server started with PID $(cat .nexustrace.pid)"
    log_info "Running at http://0.0.0.0:5050"
    log_info "Use './stop.sh' to stop the server"

    # Wait for server to be ready
    sleep 2
    if curl -s http://localhost:5050/ > /dev/null 2>&1; then
        log_info "Server is ready!"
    else
        log_warn "Server may still be starting up..."
    fi
fi
