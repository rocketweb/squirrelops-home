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
#   --subnet <cidr>     Override the auto-detected private /22 to /30 LAN
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
SQUIRRELOPS_SENSOR_VERSION="2.0.3"
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
PORT_WAS_SET=0
SUBNET_WAS_SET=0
PROFILE_WAS_SET=0

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
  --subnet <cidr>     Override the auto-detected private /22 to /30 LAN
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
            SUBNET_WAS_SET=1
            shift 2
            ;;
        --port)
            [ -n "${2:-}" ] || error "--port requires a port number"
            PORT="$2"
            PORT_WAS_SET=1
            shift 2
            ;;
        --profile)
            [ -n "${2:-}" ] || error "--profile requires one of: lite, standard, full"
            case "$2" in
                lite|standard|full) PROFILE="$2" ;;
                *) error "Invalid profile '$2'. Must be one of: lite, standard, full" ;;
            esac
            PROFILE_WAS_SET=1
            shift 2
            ;;
        *)
            error "Unknown option: $1. Use --help for usage."
            ;;
    esac
done
if [[ ! "$PORT" =~ ^[0-9]{1,5}$ ]] \
    || [ "$((10#$PORT))" -lt 1 ] \
    || [ "$((10#$PORT))" -gt 65535 ]
then
    error "--port must be an integer from 1 through 65535"
fi
PORT="$((10#$PORT))"

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

detect_platform() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64)   PLATFORM="linux/amd64" ;;
        aarch64|arm64)  PLATFORM="linux/arm64" ;;
        *)              error "Unsupported architecture: $ARCH" ;;
    esac
}

normalize_private_subnet() {
    local cidr="$1"
    local address
    local prefix_text
    local prefix
    local a
    local b
    local c
    local d
    local octet
    local ip_number
    local mask
    local network

    [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] \
        || return 1
    address="${cidr%/*}"
    prefix_text="${cidr#*/}"
    [[ "$prefix_text" =~ ^(0|[1-9][0-9]?)$ ]] || return 1
    prefix=$((10#$prefix_text))
    # The helper permits at most 1,024 scan targets. /31 and /32 do not
    # describe a useful directly connected home LAN.
    [ "$prefix" -ge 22 ] && [ "$prefix" -le 30 ] || return 1

    IFS='.' read -r a b c d <<< "$address"
    for octet in "$a" "$b" "$c" "$d"; do
        [[ "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
        [ "$((10#$octet))" -le 255 ] || return 1
    done
    a=$((10#$a))
    b=$((10#$b))
    c=$((10#$c))
    d=$((10#$d))

    if ! { [ "$a" -eq 10 ] \
        || { [ "$a" -eq 172 ] && [ "$b" -ge 16 ] && [ "$b" -le 31 ]; } \
        || { [ "$a" -eq 192 ] && [ "$b" -eq 168 ]; }; }
    then
        return 1
    fi

    ip_number=$(( (a << 24) | (b << 16) | (c << 8) | d ))
    mask=$(( (0xffffffff << (32 - prefix)) & 0xffffffff ))
    network=$((ip_number & mask))
    printf '%d.%d.%d.%d/%d\n' \
        "$(( (network >> 24) & 255 ))" \
        "$(( (network >> 16) & 255 ))" \
        "$(( (network >> 8) & 255 ))" \
        "$(( network & 255 ))" \
        "$prefix"
}

detect_lan_subnet() {
    local route_output
    local route_line
    local interface
    local source_ip
    local address_output
    local candidate

    command -v ip >/dev/null 2>&1 || return 1
    route_output="$(ip -4 route show default 2>/dev/null)" || return 1
    route_line="$(
        printf '%s\n' "$route_output" \
            | awk '
                NF {
                    line = $0
                    count++
                }
                END {
                    if (count != 1) {
                        exit 1
                    }
                    print line
                }
            '
    )" || return 1
    interface="$(
        printf '%s\n' "$route_line" \
            | awk '{
                for (i = 1; i < NF; i++) {
                    if ($i == "dev") {
                        print $(i + 1)
                        exit
                    }
                }
            }'
    )"
    source_ip="$(
        printf '%s\n' "$route_line" \
            | awk '{
                for (i = 1; i < NF; i++) {
                    if ($i == "src") {
                        print $(i + 1)
                        exit
                    }
                }
            }'
    )"
    [[ "$interface" =~ ^[A-Za-z0-9_.:-]+$ ]] || return 1

    address_output="$(
        ip -4 -o addr show dev "$interface" scope global 2>/dev/null
    )" || return 1
    candidate="$(
        printf '%s\n' "$address_output" \
            | awk -v source="$source_ip" '
                {
                    for (i = 1; i < NF; i++) {
                        if ($i == "inet") {
                            split($(i + 1), parts, "/")
                            if (source == "" || parts[1] == source) {
                                candidate = $(i + 1)
                                count++
                            }
                        }
                    }
                }
                END {
                    if (count != 1) {
                        exit 1
                    }
                    print candidate
                }
            '
    )" || return 1
    normalize_private_subnet "$candidate"
}

resolve_lan_subnet() {
    if [ -n "$SUBNET" ] && [ "$SUBNET" != "auto" ]; then
        normalize_private_subnet "$SUBNET"
        return
    fi
    detect_lan_subnet
}

read_compose_setting() {
    local key="$1"
    local file="$2"
    local value

    value="$(
        awk -v expected="${key}:" '
            $1 == expected {
                $1 = ""
                sub(/^[[:space:]]+/, "")
                value = $0
                count++
            }
            END {
                if (count == 0) {
                    exit 1
                }
                if (count > 1) {
                    exit 2
                }
                print value
            }
        ' "$file"
    )" || return $?
    case "$value" in
        \"*\")
            value="${value#\"}"
            value="${value%\"}"
            ;;
        \'*\')
            value="${value#\'}"
            value="${value%\'}"
            ;;
    esac
    [ -n "$value" ] || return 1
    printf '%s\n' "$value"
}

load_existing_configuration() {
    local value
    local status

    if [ "$PORT_WAS_SET" -eq 0 ]; then
        if value="$(read_compose_setting SQUIRRELOPS_PORT "$COMPOSE_FILE")"; then
            [[ "$value" =~ ^[0-9]{1,5}$ ]] \
                && [ "$((10#$value))" -ge 1 ] \
                && [ "$((10#$value))" -le 65535 ] \
                || error "Existing SQUIRRELOPS_PORT is invalid; pass --port explicitly."
            PORT="$((10#$value))"
        else
            status=$?
            [ "$status" -eq 1 ] \
                || error "Existing compose file defines SQUIRRELOPS_PORT more than once."
        fi
    fi

    if [ "$SUBNET_WAS_SET" -eq 0 ]; then
        if value="$(read_compose_setting SQUIRRELOPS_SUBNET "$COMPOSE_FILE")"; then
            SUBNET="$value"
        else
            status=$?
            [ "$status" -eq 1 ] \
                || error "Existing compose file defines SQUIRRELOPS_SUBNET more than once."
        fi
    fi

    if [ "$PROFILE_WAS_SET" -eq 0 ]; then
        if value="$(read_compose_setting SQUIRRELOPS_PROFILE "$COMPOSE_FILE")"; then
            case "$value" in
                lite|standard|full) PROFILE="$value" ;;
                *) error "Existing SQUIRRELOPS_PROFILE is invalid; pass --profile explicitly." ;;
            esac
        else
            status=$?
            [ "$status" -eq 1 ] \
                || error "Existing compose file defines SQUIRRELOPS_PROFILE more than once."
        fi
    fi
}

write_compose_file() {
    local output_file="$1"
    local env_block

    env_block="      SQUIRRELOPS_DATA_DIR: /app/data"
    env_block="${env_block}\n      SQUIRRELOPS_PORT: \"${PORT}\""
    env_block="${env_block}\n      SQUIRRELOPS_SUBNET: \"${LAN_SUBNET}\""
    if [ -n "$PROFILE" ]; then
        env_block="${env_block}\n      SQUIRRELOPS_PROFILE: \"${PROFILE}\""
    fi

    cat > "$output_file" <<EOF
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
$(echo -e "$env_block")
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
    chmod 600 "$output_file"
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
    local new_compose
    local previous_compose

    preflight
    validate_release_image

    info "SquirrelOps Home Sensor — Upgrade to v${SQUIRRELOPS_SENSOR_VERSION}"

    if [ ! -f "$COMPOSE_FILE" ]; then
        error "No existing installation found at $INSTALL_DIR. Run without --upgrade to install."
    fi

    detect_platform
    load_existing_configuration
    if ! LAN_SUBNET="$(resolve_lan_subnet)"; then
        error "Could not safely resolve the LAN subnet. Pass --subnet with the directly connected private CIDR."
    fi
    info "Using LAN subnet ${LAN_SUBNET}"

    if ! grep -qx '  network-helper:' "$COMPOSE_FILE"; then
        warn "Migrating the legacy root/host-network sensor to the constrained 2.0 topology."
    fi

    new_compose="$(mktemp "$INSTALL_DIR/.docker-compose.XXXXXX")"
    write_compose_file "$new_compose"
    if ! docker compose -f "$new_compose" config -q; then
        rm -f "$new_compose"
        error "Generated Docker Compose configuration is invalid; existing installation was not changed."
    fi

    info "Pulling the pinned sensor image for v${SQUIRRELOPS_SENSOR_VERSION} ($PLATFORM)..."
    docker pull --platform "$PLATFORM" "$IMAGE_REF"

    previous_compose="$(mktemp "$INSTALL_DIR/.docker-compose.previous.XXXXXX")"
    cp -p "$COMPOSE_FILE" "$previous_compose"
    info "Stopping the existing sensor topology..."
    docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
    mv "$new_compose" "$COMPOSE_FILE"

    info "Starting the constrained sensor and network-helper topology..."
    if ! docker compose -f "$COMPOSE_FILE" up -d; then
        warn "The 2.0 topology did not start; restoring the previous compose file."
        docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
        mv "$previous_compose" "$COMPOSE_FILE"
        docker compose -f "$COMPOSE_FILE" up -d 2>/dev/null || true
        error "Upgrade failed and the previous compose configuration was restored."
    fi
    if ! health_check "$PORT"; then
        warn "The 2.0 sensor did not become healthy; restoring the previous compose file."
        docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
        mv "$previous_compose" "$COMPOSE_FILE"
        docker compose -f "$COMPOSE_FILE" up -d 2>/dev/null || true
        error "Upgrade health check failed and the previous compose configuration was restored."
    fi
    rm -f "$previous_compose"

    echo ""
    info "Upgrade to v${SQUIRRELOPS_SENSOR_VERSION} complete."
}

# =======================================================================
# ACTION: Install (default)
# =======================================================================
do_install() {
    local new_compose

    preflight
    validate_release_image

    info "SquirrelOps Home Sensor — Install v${SQUIRRELOPS_SENSOR_VERSION}"

    # -------------------------------------------------------------------
    # Detect architecture
    # -------------------------------------------------------------------
    detect_platform
    info "Detected architecture: $ARCH ($PLATFORM)"
    if ! LAN_SUBNET="$(resolve_lan_subnet)"; then
        error "Could not safely auto-detect the LAN subnet. Pass --subnet with the directly connected private CIDR."
    fi
    info "Using LAN subnet ${LAN_SUBNET}"

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
    # Write docker-compose.yml
    # -------------------------------------------------------------------
    new_compose="$(mktemp "$INSTALL_DIR/.docker-compose.XXXXXX")"
    write_compose_file "$new_compose"
    if ! docker compose -f "$new_compose" config -q; then
        rm -f "$new_compose"
        error "Generated Docker Compose configuration is invalid."
    fi
    mv "$new_compose" "$COMPOSE_FILE"

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
    echo "  Subnet:       $LAN_SUBNET"
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
