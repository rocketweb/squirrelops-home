#!/usr/bin/env bash
#
# SquirrelOps Home Sensor — Linux Install Script
#
# Usage:
#   Verify the release checksum, review the script, then: sudo bash install.sh
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
# Release template. Update the version for each release. The release workflow
# replaces the digest placeholder; a checkout copy fails closed for install and
# upgrade operations.
# -----------------------------------------------------------------------
SQUIRRELOPS_SENSOR_VERSION="2.0.0"
SQUIRRELOPS_IMAGE_DIGEST="__RELEASE_IMAGE_DIGEST__"

INSTALL_DIR="/opt/squirrelops"
IMAGE="ghcr.io/rocketweb/squirrelops-sensor"
IMAGE_REF="${IMAGE}@${SQUIRRELOPS_IMAGE_DIGEST}"
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
SquirrelOps Home Sensor — Linux Installer v${SQUIRRELOPS_SENSOR_VERSION}

Usage:
  sudo bash install.sh [OPTIONS]
  Download install.sh and install.sh.sha256 from a pinned GitHub release,
  verify the checksum, review the script, then run: sudo bash install.sh

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

validate_release_image() {
    if [[ ! "$SQUIRRELOPS_IMAGE_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        error "Release installer is missing its pinned container digest. Download install.sh from a published release."
    fi
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
    validate_release_image

    info "SquirrelOps Home Sensor — Upgrade to v${SQUIRRELOPS_SENSOR_VERSION}"

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

    info "Pulling the pinned sensor image for v${SQUIRRELOPS_SENSOR_VERSION} ($PLATFORM)..."
    docker pull --platform "$PLATFORM" "$IMAGE_REF"

    # Update the compose file to the immutable manifest-list digest.
    if command -v sed >/dev/null 2>&1; then
        sed -i.bak "s|image: ${IMAGE}.*|image: ${IMAGE_REF}|" "$COMPOSE_FILE"
        rm -f "${COMPOSE_FILE}.bak"
        info "Updated $COMPOSE_FILE to v${SQUIRRELOPS_SENSOR_VERSION}"
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
    info "Upgrade to v${SQUIRRELOPS_SENSOR_VERSION} complete."
}

# =======================================================================
# ACTION: Install (default)
# =======================================================================
do_install() {
    preflight
    validate_release_image

    info "SquirrelOps Home Sensor — Install v${SQUIRRELOPS_SENSOR_VERSION}"

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
    LAN_SUBNET="${SUBNET:-192.168.1.0/24}"
    ENV_BLOCK="      SQUIRRELOPS_DATA_DIR: /app/data"
    ENV_BLOCK="${ENV_BLOCK}\n      SQUIRRELOPS_PORT: \"${PORT}\""
    ENV_BLOCK="${ENV_BLOCK}\n      SQUIRRELOPS_SUBNET: \"${LAN_SUBNET}\""
    if [ -n "$PROFILE" ]; then
        ENV_BLOCK="${ENV_BLOCK}\n      SQUIRRELOPS_PROFILE: \"${PROFILE}\""
    fi

    # -------------------------------------------------------------------
    # Write docker-compose.yml
    # -------------------------------------------------------------------
    cat > "$COMPOSE_FILE" <<EOF
# SquirrelOps Home Sensor v${SQUIRRELOPS_SENSOR_VERSION} — managed by install.sh
# Do not edit manually — re-run the installer to update.

services:
  network-helper:
    image: ${IMAGE_REF}
    network_mode: host
    user: "0:0"
    command:
      - /app/.venv/bin/python
      - -m
      - squirrelops_home_sensor.privileged.linux_sidecar
    cap_drop:
      - ALL
    cap_add:
      - NET_RAW
      - NET_ADMIN
    security_opt:
      - no-new-privileges:true
    read_only: true
    volumes:
      - helper_socket:/run/squirrelops
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=16m
    environment:
      SQUIRRELOPS_NETWORK_HELPER_SOCKET: /run/squirrelops/network-helper.sock
      SQUIRRELOPS_SENSOR_UID: "10001"
      SQUIRRELOPS_SENSOR_BRIDGE_IP: 172.30.0.2
      SQUIRRELOPS_LAN_SUBNET: "${LAN_SUBNET}"
      SQUIRRELOPS_NETWORK_INTERFACE: auto
    healthcheck:
      test:
        - CMD
        - /app/.venv/bin/python
        - -m
        - squirrelops_home_sensor.privileged.linux_sidecar
        - --healthcheck
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 5s
    restart: unless-stopped

  sensor:
    image: ${IMAGE_REF}
    user: "10001:10001"
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    read_only: true
    ports:
      - "${PORT}:${PORT}"
    volumes:
      - sensor_data:/app/data
      - helper_socket:/run/squirrelops:ro
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=64m
    environment:
$(echo -e "$ENV_BLOCK")
      SQUIRRELOPS_NETWORK_HELPER_SOCKET: /run/squirrelops/network-helper.sock
      SQUIRRELOPS_SENSOR_BRIDGE_IP: 172.30.0.2
    depends_on:
      network-helper:
        condition: service_healthy
    networks:
      sensor_private:
        ipv4_address: 172.30.0.2
    restart: unless-stopped

networks:
  sensor_private:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/28

volumes:
  sensor_data:
  helper_socket:
EOF

    info "Configuration written to $COMPOSE_FILE"

    # -------------------------------------------------------------------
    # Pull image
    # -------------------------------------------------------------------
    info "Pulling the pinned sensor image for v${SQUIRRELOPS_SENSOR_VERSION} ($PLATFORM)..."
    docker pull --platform "$PLATFORM" "$IMAGE_REF"

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
    echo -e "${BOLD}  SquirrelOps Home Sensor v${SQUIRRELOPS_SENSOR_VERSION}${NC}"
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
