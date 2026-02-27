#!/usr/bin/env bash
#
# SquirrelOps Home Sensor — Linux Install Script
#
# Usage:
#   curl -fsSL https://get.squirrelops.io/install.sh | sudo bash
#   sudo bash install.sh [OPTIONS]
#
# Options:
#   --help              Show this help message
#   --uninstall         Remove SquirrelOps sensor and optionally its data
#   --upgrade           Pull latest pinned version and restart
#   --subnet <cidr>     Set sensor subnet (e.g. 192.168.1.0/24)
#   --port <port>       Set API port (default: 8443)
#   --profile <name>    Set resource profile (lite|standard|full)
#
# Requirements: Docker, docker compose (v2 plugin)
#
set -euo pipefail

# -----------------------------------------------------------------------
# Version pinning — update this for each release
# -----------------------------------------------------------------------
SQUIRRELOPS_VERSION="1.0.0"

INSTALL_DIR="/opt/squirrelops"
IMAGE="ghcr.io/rocketweb/squirrelops-sensor"
COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"

# Defaults
PORT="8443"
SUBNET=""
PROFILE=""
ACTION="install"

# -----------------------------------------------------------------------
# Colors (if terminal supports them)
# -----------------------------------------------------------------------
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BOLD='' NC=''
fi

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

# -----------------------------------------------------------------------
# Usage / help
# -----------------------------------------------------------------------
usage() {
    cat <<EOF
SquirrelOps Home Sensor — Linux Installer v${SQUIRRELOPS_VERSION}

Usage:
  sudo bash install.sh [OPTIONS]
  curl -fsSL https://get.squirrelops.io/install.sh | sudo bash

Options:
  --help              Show this help message and exit
  --uninstall         Remove SquirrelOps sensor and optionally its data
  --upgrade           Pull the pinned version image and restart the sensor
  --subnet <cidr>     Set sensor subnet (e.g. 192.168.1.0/24)
  --port <port>       Set API port (default: 8443)
  --profile <name>    Set resource profile: lite, standard, or full

Examples:
  sudo bash install.sh
  sudo bash install.sh --subnet 192.168.1.0/24 --profile standard
  sudo bash install.sh --upgrade
  sudo bash install.sh --uninstall
EOF
    exit 0
}

# -----------------------------------------------------------------------
# Parse arguments
# -----------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --help|-h)
            usage
            ;;
        --uninstall)
            ACTION="uninstall"
            shift
            ;;
        --upgrade)
            ACTION="upgrade"
            shift
            ;;
        --subnet)
            [ -n "${2:-}" ] || error "--subnet requires a CIDR argument (e.g. 192.168.1.0/24)"
            SUBNET="$2"
            shift 2
            ;;
        --port)
            [ -n "${2:-}" ] || error "--port requires a port number"
            PORT="$2"
            shift 2
            ;;
        --profile)
            [ -n "${2:-}" ] || error "--profile requires one of: lite, standard, full"
            case "$2" in
                lite|standard|full) PROFILE="$2" ;;
                *) error "Invalid profile '$2'. Must be one of: lite, standard, full" ;;
            esac
            shift 2
            ;;
        *)
            error "Unknown option: $1. Use --help for usage."
            ;;
    esac
done

# -----------------------------------------------------------------------
# Health check function — polls /system/health for up to 30 seconds
# -----------------------------------------------------------------------
health_check() {
    local port="${1:-$PORT}"
    local url="https://localhost:${port}/system/health"
    local max_attempts=15
    local attempt=0

    info "Running health check against $url ..."
    while [ "$attempt" -lt "$max_attempts" ]; do
        attempt=$((attempt + 1))
        if curl -fsSk --max-time 2 "$url" >/dev/null 2>&1; then
            info "Health check passed — sensor is running."
            return 0
        fi
        sleep 2
    done

    warn "Health check failed after 30 seconds."
    warn "The sensor may still be starting. Check logs with:"
    warn "  docker compose -f $COMPOSE_FILE logs -f"
    return 1
}

# -----------------------------------------------------------------------
# Preflight checks (required for all actions)
# -----------------------------------------------------------------------
preflight() {
    # Must be root
    [ "$(id -u)" -eq 0 ] || error "This script must be run as root (use sudo)"

    # Docker installed?
    command -v docker >/dev/null 2>&1 || error "Docker is not installed. Install Docker first: https://docs.docker.com/get-docker/"

    # docker compose v2?
    docker compose version >/dev/null 2>&1 || error "docker compose (v2) is required. Install: https://docs.docker.com/compose/install/"
}

# =======================================================================
# ACTION: Uninstall
# =======================================================================
do_uninstall() {
    preflight

    info "SquirrelOps Home Sensor — Uninstall"

    if [ ! -f "$COMPOSE_FILE" ]; then
        warn "No installation found at $INSTALL_DIR"
        exit 0
    fi

    info "Stopping sensor container..."
    docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true

    # Ask about data volume
    echo ""
    echo -n "Remove sensor data volume? This deletes all collected data. [y/N] "
    read -r REMOVE_DATA </dev/tty 2>/dev/null || REMOVE_DATA="n"
    if [ "$REMOVE_DATA" = "y" ] || [ "$REMOVE_DATA" = "Y" ]; then
        info "Removing data volume..."
        docker volume rm squirrelops_sensor_data 2>/dev/null || true
    else
        info "Data volume preserved."
    fi

    info "Removing install directory $INSTALL_DIR ..."
    rm -rf "$INSTALL_DIR"

    echo ""
    info "SquirrelOps sensor has been uninstalled."
    if [ "$REMOVE_DATA" != "y" ] && [ "$REMOVE_DATA" != "Y" ]; then
        info "Data volume 'squirrelops_sensor_data' was kept. Remove manually with:"
        info "  docker volume rm squirrelops_sensor_data"
    fi
}

# =======================================================================
# ACTION: Upgrade
# =======================================================================
do_upgrade() {
    preflight

    info "SquirrelOps Home Sensor — Upgrade to v${SQUIRRELOPS_VERSION}"

    if [ ! -f "$COMPOSE_FILE" ]; then
        error "No existing installation found at $INSTALL_DIR. Run without --upgrade to install."
    fi

    # Detect architecture
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64)   PLATFORM="linux/amd64" ;;
        aarch64|arm64)   PLATFORM="linux/arm64" ;;
        *)               error "Unsupported architecture: $ARCH" ;;
    esac

    info "Pulling sensor image v${SQUIRRELOPS_VERSION} for $PLATFORM..."
    docker pull --platform "$PLATFORM" "$IMAGE:$SQUIRRELOPS_VERSION"

    # Update the image tag in the compose file to the new version
    if command -v sed >/dev/null 2>&1; then
        sed -i.bak "s|image: ${IMAGE}:.*|image: ${IMAGE}:${SQUIRRELOPS_VERSION}|" "$COMPOSE_FILE"
        rm -f "${COMPOSE_FILE}.bak"
        info "Updated $COMPOSE_FILE to v${SQUIRRELOPS_VERSION}"
    fi

    info "Restarting sensor..."
    docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
    docker compose -f "$COMPOSE_FILE" up -d

    # Read port from compose file for health check
    local check_port
    check_port=$(grep 'SQUIRRELOPS_PORT' "$COMPOSE_FILE" | head -1 | sed 's/.*: *"\{0,1\}\([0-9]*\)"\{0,1\}/\1/' 2>/dev/null || echo "8443")
    [ -z "$check_port" ] && check_port="8443"

    health_check "$check_port"

    echo ""
    info "Upgrade to v${SQUIRRELOPS_VERSION} complete."
}

# =======================================================================
# ACTION: Install (default)
# =======================================================================
do_install() {
    preflight

    info "SquirrelOps Home Sensor — Install v${SQUIRRELOPS_VERSION}"

    # -------------------------------------------------------------------
    # Detect architecture
    # -------------------------------------------------------------------
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64)   PLATFORM="linux/amd64" ;;
        aarch64|arm64)   PLATFORM="linux/arm64" ;;
        *)               error "Unsupported architecture: $ARCH" ;;
    esac
    info "Detected architecture: $ARCH ($PLATFORM)"

    # -------------------------------------------------------------------
    # Stop existing installation (if upgrading in place)
    # -------------------------------------------------------------------
    if [ -f "$COMPOSE_FILE" ]; then
        warn "Existing installation found. Stopping..."
        docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
    fi

    # -------------------------------------------------------------------
    # Create install directory
    # -------------------------------------------------------------------
    mkdir -p "$INSTALL_DIR"

    # -------------------------------------------------------------------
    # Build environment block for docker-compose.yml
    # -------------------------------------------------------------------
    ENV_BLOCK="      SQUIRRELOPS_DATA_DIR: /app/data"
    ENV_BLOCK="${ENV_BLOCK}\n      SQUIRRELOPS_PORT: \"${PORT}\""
    if [ -n "$SUBNET" ]; then
        ENV_BLOCK="${ENV_BLOCK}\n      SQUIRRELOPS_SUBNET: \"${SUBNET}\""
    fi
    if [ -n "$PROFILE" ]; then
        ENV_BLOCK="${ENV_BLOCK}\n      SQUIRRELOPS_PROFILE: \"${PROFILE}\""
    fi

    # -------------------------------------------------------------------
    # Write docker-compose.yml
    # -------------------------------------------------------------------
    cat > "$COMPOSE_FILE" <<EOF
# SquirrelOps Home Sensor v${SQUIRRELOPS_VERSION} — managed by install.sh
# Do not edit manually — re-run the installer to update.

services:
  sensor:
    image: ${IMAGE}:${SQUIRRELOPS_VERSION}
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN
    volumes:
      - sensor_data:/app/data
    environment:
$(echo -e "$ENV_BLOCK")
    restart: unless-stopped

volumes:
  sensor_data:
EOF

    info "Configuration written to $COMPOSE_FILE"

    # -------------------------------------------------------------------
    # Pull image
    # -------------------------------------------------------------------
    info "Pulling sensor image v${SQUIRRELOPS_VERSION} for $PLATFORM..."
    docker pull --platform "$PLATFORM" "$IMAGE:$SQUIRRELOPS_VERSION"

    # -------------------------------------------------------------------
    # Start sensor
    # -------------------------------------------------------------------
    info "Starting sensor..."
    docker compose -f "$COMPOSE_FILE" up -d

    # -------------------------------------------------------------------
    # Health check
    # -------------------------------------------------------------------
    health_check "$PORT"

    # -------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------
    echo ""
    echo -e "${BOLD}=========================================${NC}"
    echo -e "${BOLD}  SquirrelOps Home Sensor v${SQUIRRELOPS_VERSION}${NC}"
    echo -e "${BOLD}  is running!${NC}"
    echo -e "${BOLD}=========================================${NC}"
    echo ""
    echo "  Install dir:  $INSTALL_DIR"
    echo "  Compose file: $COMPOSE_FILE"
    echo "  API port:     $PORT"
    [ -n "$SUBNET" ]  && echo "  Subnet:       $SUBNET"
    [ -n "$PROFILE" ] && echo "  Profile:      $PROFILE"
    echo ""
    echo "  Logs:      docker compose -f $COMPOSE_FILE logs -f"
    echo "  Stop:      docker compose -f $COMPOSE_FILE down"
    echo "  Upgrade:   re-run with --upgrade"
    echo "  Uninstall: re-run with --uninstall"
    echo ""
}

# =======================================================================
# Dispatch
# =======================================================================
case "$ACTION" in
    install)    do_install   ;;
    upgrade)    do_upgrade   ;;
    uninstall)  do_uninstall ;;
esac
