#!/usr/bin/env bash
#
# SquirrelOps Home — Uninstall Script
#
# Removes the SquirrelOps Home app, sensor, and related files.
# Must be run with sudo.
#
# Usage:
#   sudo bash /Library/SquirrelOps/sensor/uninstall.sh
#
set -euo pipefail

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

# ---------------------------------------------------------------------------
# Check for root
# ---------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run with sudo."
    echo "  sudo bash $0"
    exit 1
fi

PLIST_NAME="com.squirrelops.sensor"
PLIST_PATH="/Library/LaunchDaemons/${PLIST_NAME}.plist"
INSTALL_DIR="/Library/SquirrelOps/sensor"
APP_PATH="/Applications/SquirrelOps Home.app"

echo ""
echo -e "${BOLD}SquirrelOps Home — Uninstaller${NC}"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Stop sensor service
# ---------------------------------------------------------------------------
if [ -f "$PLIST_PATH" ]; then
    info "Stopping sensor service..."
    launchctl bootout system "$PLIST_PATH" 2>/dev/null || true
    sleep 1
    info "Sensor service stopped."
else
    info "No sensor service found (already removed or never installed)."
fi

# ---------------------------------------------------------------------------
# Step 2: Remove app from /Applications
# ---------------------------------------------------------------------------
if [ -d "$APP_PATH" ]; then
    info "Removing $APP_PATH..."
    rm -rf "$APP_PATH"
    info "App removed."
else
    info "App not found at $APP_PATH (already removed or installed elsewhere)."
fi

# ---------------------------------------------------------------------------
# Step 3: Ask whether to remove data
# ---------------------------------------------------------------------------
REMOVE_DATA="n"
DATA_DIR="$INSTALL_DIR/data"

if [ -d "$DATA_DIR" ]; then
    echo ""
    echo -e "${YELLOW}The sensor data directory contains your device database,"
    echo -e "alert history, and TLS certificates.${NC}"
    echo ""
    # Read from /dev/tty to work even when piped
    printf "  Remove sensor data at %s? [y/N] " "$DATA_DIR"
    read -r REMOVE_DATA < /dev/tty || REMOVE_DATA="n"
    echo ""
fi

# ---------------------------------------------------------------------------
# Step 4: Remove sensor venv and plist
# ---------------------------------------------------------------------------
if [ -d "$INSTALL_DIR/venv" ]; then
    info "Removing sensor venv..."
    rm -rf "$INSTALL_DIR/venv"
fi

if [ -f "$PLIST_PATH" ]; then
    info "Removing launchd plist..."
    rm -f "$PLIST_PATH"
fi

# Remove the plist template and uninstall script from install dir
rm -f "$INSTALL_DIR/com.squirrelops.sensor.plist"
rm -f "$INSTALL_DIR/uninstall.sh"

# Remove config (but not data, unless user opted in)
rm -f "$INSTALL_DIR/config.yaml"
rm -f "$INSTALL_DIR/config.yaml.bak"

# ---------------------------------------------------------------------------
# Step 5: Conditionally remove data
# ---------------------------------------------------------------------------
if [[ "$REMOVE_DATA" =~ ^[Yy]$ ]]; then
    info "Removing sensor data..."
    rm -rf "$DATA_DIR"
    rm -rf "$INSTALL_DIR/logs"
    info "Data removed."
else
    info "Keeping sensor data at $DATA_DIR"
fi

# Remove install dir if empty
if [ -d "$INSTALL_DIR" ]; then
    rmdir "$INSTALL_DIR" 2>/dev/null || true
fi

# Remove parent dir if empty
if [ -d "/Library/SquirrelOps" ]; then
    rmdir "/Library/SquirrelOps" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Step 6: Forget package receipts
# ---------------------------------------------------------------------------
info "Forgetting package receipts..."
pkgutil --forget com.squirrelops.home.app 2>/dev/null || true
pkgutil --forget com.squirrelops.home.sensor 2>/dev/null || true
pkgutil --forget com.squirrelops.home 2>/dev/null || true

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}=========================================${NC}"
echo -e "${BOLD}  SquirrelOps Home — Uninstalled${NC}"
echo -e "${BOLD}=========================================${NC}"
echo ""
info "All SquirrelOps Home components have been removed."
if [[ ! "$REMOVE_DATA" =~ ^[Yy]$ ]] && [ -d "$DATA_DIR" ]; then
    warn "Sensor data was preserved at $DATA_DIR"
    warn "To remove it manually: sudo rm -rf $INSTALL_DIR"
fi
echo ""
