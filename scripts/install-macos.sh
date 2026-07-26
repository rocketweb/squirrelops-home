#!/usr/bin/env bash
#
# SquirrelOps Home Sensor — macOS Install Script
#
# Installs the sensor as a launchd user agent on macOS.
#
# Usage:
#   bash scripts/install-macos.sh
#
# Requirements: Python 3.11+, macOS 14+
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
INSTALL_DIR="$HOME/.squirrelops/sensor"
DATA_DIR="$INSTALL_DIR/data"
CONFIG_DIR="$INSTALL_DIR/config"
LOG_DIR="$INSTALL_DIR/logs"
RUN_DIR="$INSTALL_DIR/run"
VENV_DIR="$INSTALL_DIR/venv"
CONFIG_FILE="$CONFIG_DIR/config.yaml"
PLIST_NAME="com.squirrelops.sensor"
PLIST_DEST="$HOME/Library/LaunchAgents/${PLIST_NAME}.plist"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SENSOR_DIR="$SCRIPT_DIR/../sensor"
PLIST_TEMPLATE="$SCRIPT_DIR/../sensor/resources/${PLIST_NAME}.plist"
REQUIRED_UV_VERSION="0.10.2"

# ---------------------------------------------------------------------------
# Colors (if terminal supports them)
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Step 1: Check for Python 3.11+
# ---------------------------------------------------------------------------
info "SquirrelOps Home Sensor — macOS Installer"
echo ""

PYTHON_CMD=""
for candidate in python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        version=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")
        major=$(echo "$version" | cut -d. -f1)
        minor=$(echo "$version" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 11 ]; then
            PYTHON_CMD="$candidate"
            info "Found Python $version at $(command -v "$candidate")"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    error "Python 3.11+ is required but not found. Install via: brew install python@3.12"
fi

# This installer is intentionally source-checkout-only. Release installs use the
# signed and notarized .pkg, which embeds the sensor and its locked dependencies.
command -v uv >/dev/null 2>&1 || {
    error "uv $REQUIRED_UV_VERSION is required. Install it from https://docs.astral.sh/uv/."
}
ACTUAL_UV_VERSION="$(uv --version | awk '{ print $2 }')"
if [ "$ACTUAL_UV_VERSION" != "$REQUIRED_UV_VERSION" ]; then
    error "uv $REQUIRED_UV_VERSION is required (found $ACTUAL_UV_VERSION)."
fi
if [ ! -f "$SENSOR_DIR/pyproject.toml" ] || [ ! -f "$SENSOR_DIR/uv.lock" ]; then
    error "A complete source checkout with sensor/pyproject.toml and sensor/uv.lock is required. Use the signed .pkg for release installs."
fi
if [ ! -f "$PLIST_TEMPLATE" ]; then
    error "LaunchAgent template is missing from the source checkout: $PLIST_TEMPLATE"
fi

# ---------------------------------------------------------------------------
# Step 2: Create directory tree
# ---------------------------------------------------------------------------
info "Creating directory tree at $INSTALL_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$RUN_DIR"
mkdir -p "$HOME/Library/LaunchAgents"
chmod 700 "$DATA_DIR" "$CONFIG_DIR" "$LOG_DIR"

# ---------------------------------------------------------------------------
# Step 3: Sync the exact locked Python environment
# ---------------------------------------------------------------------------
info "Syncing the locked sensor environment..."
UV_PROJECT_ENVIRONMENT="$VENV_DIR" uv sync \
    --project "$SENSOR_DIR" \
    --python "$PYTHON_CMD" \
    --frozen \
    --no-dev \
    --no-editable

# ---------------------------------------------------------------------------
# Step 4: Generate default config if not exists
# ---------------------------------------------------------------------------
if [ -f "$CONFIG_FILE" ]; then
    info "Config already exists at $CONFIG_FILE"
else
    info "Generating default config.yaml..."
    cat > "$CONFIG_FILE" << YAML
# SquirrelOps Home Sensor — Configuration
# See documentation for all available options.

profile: standard

sensor:
  name: SquirrelOps Home Sensor
  data_dir: "$DATA_DIR"
  port: 8443

network:
  interface: auto
  scan_interval: 300

alerts:
  retention_days: 90

pairing:
  socket_path: "$RUN_DIR/pairing.sock"
YAML
    info "Default config written to $CONFIG_FILE"
fi
chmod 700 "$DATA_DIR" "$CONFIG_DIR"
chmod 755 "$RUN_DIR"
chmod 600 "$CONFIG_FILE"

# ---------------------------------------------------------------------------
# Step 5: Generate launchd plist from template
# ---------------------------------------------------------------------------
info "Generating launchd plist..."

VENV_PYTHON_PATH="$VENV_DIR/bin/python"

PLIST_CONTENT=$(cat "$PLIST_TEMPLATE")

# Replace placeholders
PLIST_CONTENT="${PLIST_CONTENT//__PYTHON_PATH__/$VENV_PYTHON_PATH}"
PLIST_CONTENT="${PLIST_CONTENT//__CONFIG_PATH__/$CONFIG_FILE}"
PLIST_CONTENT="${PLIST_CONTENT//__INSTALL_DIR__/$INSTALL_DIR}"
PLIST_CONTENT="${PLIST_CONTENT//__DATA_DIR__/$DATA_DIR}"
PLIST_CONTENT="${PLIST_CONTENT//__LOG_DIR__/$LOG_DIR}"

# ---------------------------------------------------------------------------
# Step 6: Install plist to ~/Library/LaunchAgents/
# ---------------------------------------------------------------------------
info "Installing plist to $PLIST_DEST"
echo "$PLIST_CONTENT" > "$PLIST_DEST"

# ---------------------------------------------------------------------------
# Step 7: Load via launchctl (unload existing first)
# ---------------------------------------------------------------------------
info "Loading sensor via launchctl..."
DOMAIN_TARGET="gui/$(id -u)"

# Unload existing service if present
if launchctl print "$DOMAIN_TARGET/$PLIST_NAME" >/dev/null 2>&1; then
    warn "Unloading existing sensor service..."
    launchctl bootout "$DOMAIN_TARGET/$PLIST_NAME" 2>/dev/null || true
    sleep 1
fi

launchctl bootstrap "$DOMAIN_TARGET" "$PLIST_DEST"
info "Sensor loaded successfully"

# ---------------------------------------------------------------------------
# Step 8: Installation summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}=========================================${NC}"
echo -e "${BOLD}  SquirrelOps Home Sensor — Installed!${NC}"
echo -e "${BOLD}=========================================${NC}"
echo ""
echo "  Install dir:  $INSTALL_DIR"
echo "  Config:       $CONFIG_FILE"
echo "  Data:         $DATA_DIR"
echo "  Logs:         $LOG_DIR/squirrelops-sensor.log"
echo "  Plist:        $PLIST_DEST"
echo "  Python:       $VENV_PYTHON_PATH"
echo ""
echo "  Status:   launchctl print gui/$(id -u)/$PLIST_NAME"
echo "  Logs:     tail -f $LOG_DIR/squirrelops-sensor.log"
echo "  Stop:     launchctl bootout gui/$(id -u)/$PLIST_NAME"
echo "  Start:    launchctl bootstrap gui/$(id -u) $PLIST_DEST"
echo ""
