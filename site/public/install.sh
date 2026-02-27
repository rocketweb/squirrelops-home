#!/usr/bin/env bash
#
# SquirrelOps Home Sensor — Install Script
#
# Usage:
#   curl -fsSL https://get.squirrelops.io/install.sh | sudo bash
#   # or
#   sudo bash install.sh
#
# Requirements: Docker, docker compose (v2 plugin)
#
set -euo pipefail

INSTALL_DIR="/opt/squirrelops"
IMAGE="ghcr.io/rocketweb/squirrelops-sensor"
COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"

# -----------------------------------------------------------------------
# Colors (if terminal supports them)
# -----------------------------------------------------------------------
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' NC=''
fi

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

# -----------------------------------------------------------------------
# Preflight checks
# -----------------------------------------------------------------------
info "SquirrelOps Home Sensor installer"

# Must be root
[ "$(id -u)" -eq 0 ] || error "This script must be run as root (use sudo)"

# Docker installed?
command -v docker >/dev/null 2>&1 || error "Docker is not installed. Install Docker first: https://docs.docker.com/get-docker/"

# docker compose v2?
docker compose version >/dev/null 2>&1 || error "docker compose (v2) is required. Install: https://docs.docker.com/compose/install/"

# -----------------------------------------------------------------------
# Detect architecture
# -----------------------------------------------------------------------
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)   PLATFORM="linux/amd64" ;;
    aarch64|arm64)   PLATFORM="linux/arm64" ;;
    *)               error "Unsupported architecture: $ARCH" ;;
esac
info "Detected architecture: $ARCH ($PLATFORM)"

# -----------------------------------------------------------------------
# Stop existing installation (if upgrading)
# -----------------------------------------------------------------------
if [ -f "$COMPOSE_FILE" ]; then
    warn "Existing installation found. Stopping..."
    docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
fi

# -----------------------------------------------------------------------
# Create install directory
# -----------------------------------------------------------------------
mkdir -p "$INSTALL_DIR"

# -----------------------------------------------------------------------
# Write docker-compose.yml
# -----------------------------------------------------------------------
cat > "$COMPOSE_FILE" << 'COMPOSE'
# SquirrelOps Home Sensor — managed by install.sh
# Do not edit manually — re-run the installer to update.

services:
  sensor:
    image: ghcr.io/rocketweb/squirrelops-sensor:latest
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN
    volumes:
      - sensor_data:/app/data
    environment:
      SQUIRRELOPS_DATA_DIR: /app/data
      SQUIRRELOPS_PORT: "8443"
    restart: unless-stopped

volumes:
  sensor_data:
COMPOSE

info "Configuration written to $COMPOSE_FILE"

# -----------------------------------------------------------------------
# Pull image
# -----------------------------------------------------------------------
info "Pulling sensor image for $PLATFORM..."
docker pull --platform "$PLATFORM" "$IMAGE:latest"

# -----------------------------------------------------------------------
# Start sensor
# -----------------------------------------------------------------------
info "Starting sensor..."
docker compose -f "$COMPOSE_FILE" up -d

# -----------------------------------------------------------------------
# Wait for startup and show pairing code
# -----------------------------------------------------------------------
info "Waiting for sensor to start..."
sleep 5

echo ""
echo "========================================="
echo "  SquirrelOps Home Sensor is running!"
echo "========================================="
echo ""
echo "View logs (including pairing code):"
echo "  docker compose -f $COMPOSE_FILE logs -f"
echo ""
echo "Stop:    docker compose -f $COMPOSE_FILE down"
echo "Update:  re-run this install script"
echo ""
