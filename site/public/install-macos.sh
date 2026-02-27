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
VENV_DIR="$INSTALL_DIR/venv"
CONFIG_FILE="$CONFIG_DIR/config.yaml"
PLIST_NAME="com.squirrelops.sensor"
PLIST_DEST="$HOME/Library/LaunchAgents/${PLIST_NAME}.plist"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLIST_TEMPLATE="$SCRIPT_DIR/../sensor/resources/${PLIST_NAME}.plist"

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

# ---------------------------------------------------------------------------
# Step 2: Create directory tree
# ---------------------------------------------------------------------------
info "Creating directory tree at $INSTALL_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$HOME/Library/LaunchAgents"

# ---------------------------------------------------------------------------
# Step 3: Create Python venv
# ---------------------------------------------------------------------------
if [ -d "$VENV_DIR" ]; then
    info "Virtual environment already exists at $VENV_DIR"
else
    info "Creating Python virtual environment..."
    "$PYTHON_CMD" -m venv "$VENV_DIR"
fi

VENV_PYTHON="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

# Upgrade pip
"$VENV_PIP" install --upgrade pip --quiet

# ---------------------------------------------------------------------------
# Step 4: Install squirrelops-home-sensor package
# ---------------------------------------------------------------------------
info "Installing squirrelops-home-sensor..."

SENSOR_DIR="$SCRIPT_DIR/../sensor"
if [ -f "$SENSOR_DIR/pyproject.toml" ]; then
    info "Installing from local source: $SENSOR_DIR"
    "$VENV_PIP" install "$SENSOR_DIR" --quiet
else
    info "Installing from PyPI..."
    "$VENV_PIP" install squirrelops-home-sensor --quiet || {
        error "Failed to install squirrelops-home-sensor. Ensure the package is available."
    }
fi

# ---------------------------------------------------------------------------
# Step 5: Generate default config if not exists
# ---------------------------------------------------------------------------
if [ -f "$CONFIG_FILE" ]; then
    info "Config already exists at $CONFIG_FILE"
else
    info "Generating default config.yaml..."
    cat > "$CONFIG_FILE" << 'YAML'
# SquirrelOps Home Sensor — Configuration
# See documentation for all available options.

profile: standard

network:
  interface: auto
  scan_interval: 300

api:
  port: 8443
  host: 0.0.0.0

data:
  retention_days: 90
YAML
    info "Default config written to $CONFIG_FILE"
fi

# ---------------------------------------------------------------------------
# Step 6: Generate launchd plist from template
# ---------------------------------------------------------------------------
info "Generating launchd plist..."

VENV_PYTHON_PATH="$VENV_DIR/bin/python"

if [ -f "$PLIST_TEMPLATE" ]; then
    PLIST_CONTENT=$(cat "$PLIST_TEMPLATE")
else
    warn "Plist template not found at $PLIST_TEMPLATE, using embedded template"
    PLIST_CONTENT='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.squirrelops.sensor</string>
    <key>ProgramArguments</key>
    <array>
        <string>__PYTHON_PATH__</string>
        <string>-m</string>
        <string>squirrelops_home_sensor</string>
        <string>--config</string>
        <string>__CONFIG_PATH__</string>
        <string>--port</string>
        <string>8443</string>
    </array>
    <key>WorkingDirectory</key>
    <string>__INSTALL_DIR__</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>SQUIRRELOPS_DATA_DIR</key>
        <string>__DATA_DIR__</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>__LOG_DIR__/squirrelops-sensor.log</string>
    <key>StandardErrorPath</key>
    <string>__LOG_DIR__/squirrelops-sensor.log</string>
    <key>ThrottleInterval</key>
    <integer>10</integer>
</dict>
</plist>'
fi

# Replace placeholders
PLIST_CONTENT="${PLIST_CONTENT//__PYTHON_PATH__/$VENV_PYTHON_PATH}"
PLIST_CONTENT="${PLIST_CONTENT//__CONFIG_PATH__/$CONFIG_FILE}"
PLIST_CONTENT="${PLIST_CONTENT//__INSTALL_DIR__/$INSTALL_DIR}"
PLIST_CONTENT="${PLIST_CONTENT//__DATA_DIR__/$DATA_DIR}"
PLIST_CONTENT="${PLIST_CONTENT//__LOG_DIR__/$LOG_DIR}"

# ---------------------------------------------------------------------------
# Step 7: Install plist to ~/Library/LaunchAgents/
# ---------------------------------------------------------------------------
info "Installing plist to $PLIST_DEST"
echo "$PLIST_CONTENT" > "$PLIST_DEST"

# ---------------------------------------------------------------------------
# Step 8: Load via launchctl (unload existing first)
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
# Step 9: Installation summary
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
