#!/usr/bin/env bash
#
# SquirrelOps Home — Development Helper Installer
#
# Builds the privileged helper from source and installs it as a system
# launchd daemon.  The helper provides ARP scanning, virtual IP aliases,
# and pfctl port forwarding to the Python sensor process.
#
# Usage:
#   sudo bash scripts/dev-install-helper.sh             # install / update
#   sudo bash scripts/dev-install-helper.sh --uninstall  # remove
#
# Requires: Xcode 16+ (or Command Line Tools with swift), macOS 14+
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_DIR="$REPO_ROOT/app"

HELPER_LABEL="com.squirrelops.helper"
HELPER_DEST="/Library/PrivilegedHelperTools/$HELPER_LABEL"
PLIST_DEST="/Library/LaunchDaemons/${HELPER_LABEL}.plist"
PLIST_TEMPLATE="$APP_DIR/Sources/SquirrelOpsHelper/Resources/launchd.plist"
SOCKET_PATH="/var/run/squirrelops-helper.sock"
LOG_FILE="/var/log/${HELPER_LABEL}.log"

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BOLD='\033[1m'; NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BOLD='' NC=''
fi

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root.  Usage: sudo bash $0"
fi

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
uninstall() {
    info "Uninstalling $HELPER_LABEL..."

    # Stop the daemon
    if launchctl print "system/$HELPER_LABEL" >/dev/null 2>&1; then
        info "Stopping daemon..."
        launchctl bootout "system/$HELPER_LABEL" 2>/dev/null || true
        sleep 1
    fi

    # Remove files
    [ -f "$HELPER_DEST" ] && rm -f "$HELPER_DEST" && info "Removed $HELPER_DEST"
    [ -f "$PLIST_DEST" ]  && rm -f "$PLIST_DEST"  && info "Removed $PLIST_DEST"
    [ -S "$SOCKET_PATH" ] && rm -f "$SOCKET_PATH"  && info "Removed $SOCKET_PATH"

    info "Done.  Helper has been uninstalled."
    exit 0
}

if [ "${1:-}" = "--uninstall" ]; then
    uninstall
fi

# ---------------------------------------------------------------------------
# Verify prerequisites
# ---------------------------------------------------------------------------
if ! command -v swift >/dev/null 2>&1; then
    error "Swift toolchain not found.  Install Xcode 16+ or Command Line Tools."
fi

if [ ! -d "$APP_DIR/Package.swift" ] && [ ! -f "$APP_DIR/Package.swift" ]; then
    error "Package.swift not found at $APP_DIR — run this from the repo root."
fi

# ---------------------------------------------------------------------------
# Step 1: Build the helper
# ---------------------------------------------------------------------------
info "Building SquirrelOpsHelper..."
CURRENT_ARCH="$(uname -m)"
BUILD_DIR="$APP_DIR/.build/${CURRENT_ARCH}-apple-macosx/debug"

(cd "$APP_DIR" && swift build --product SquirrelOpsHelper 2>&1) || {
    error "Swift build failed.  Check Xcode installation and try again."
}

HELPER_BIN="$BUILD_DIR/SquirrelOpsHelper"
if [ ! -f "$HELPER_BIN" ]; then
    error "Helper binary not found at $HELPER_BIN after build."
fi

info "Built: $HELPER_BIN"

# ---------------------------------------------------------------------------
# Step 2: Stop existing daemon if running
# ---------------------------------------------------------------------------
if launchctl print "system/$HELPER_LABEL" >/dev/null 2>&1; then
    warn "Stopping existing helper daemon..."
    launchctl bootout "system/$HELPER_LABEL" 2>/dev/null || true
    sleep 1
fi

# Remove stale socket
[ -S "$SOCKET_PATH" ] && rm -f "$SOCKET_PATH"

# ---------------------------------------------------------------------------
# Step 3: Install binary
# ---------------------------------------------------------------------------
info "Installing helper to $HELPER_DEST"
mkdir -p "$(dirname "$HELPER_DEST")"
cp "$HELPER_BIN" "$HELPER_DEST"
chown root:wheel "$HELPER_DEST"
chmod 755 "$HELPER_DEST"

# ---------------------------------------------------------------------------
# Step 4: Install launchd plist
# ---------------------------------------------------------------------------
info "Installing launchd plist to $PLIST_DEST"

if [ -f "$PLIST_TEMPLATE" ]; then
    cp "$PLIST_TEMPLATE" "$PLIST_DEST"
else
    # Fallback: generate from scratch
    warn "Plist template not found, generating..."
    cat > "$PLIST_DEST" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.squirrelops.helper</string>
    <key>Program</key>
    <string>/Library/PrivilegedHelperTools/com.squirrelops.helper</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/com.squirrelops.helper.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/com.squirrelops.helper.log</string>
</dict>
</plist>
PLIST
fi

chown root:wheel "$PLIST_DEST"
chmod 644 "$PLIST_DEST"

# ---------------------------------------------------------------------------
# Step 5: Load the daemon
# ---------------------------------------------------------------------------
info "Loading helper daemon..."
launchctl bootstrap system "$PLIST_DEST" 2>/dev/null || {
    error "Failed to load daemon.  Check: sudo launchctl bootstrap system $PLIST_DEST"
}

# ---------------------------------------------------------------------------
# Step 6: Verify
# ---------------------------------------------------------------------------
info "Waiting for helper to start..."
TIMEOUT=10
ELAPSED=0

while [ "$ELAPSED" -lt "$TIMEOUT" ]; do
    if [ -S "$SOCKET_PATH" ]; then
        info "Helper is running — socket at $SOCKET_PATH"
        break
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done

if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
    warn "Socket not found after ${TIMEOUT}s.  Check logs: tail -f $LOG_FILE"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}=========================================${NC}"
echo -e "${BOLD}  SquirrelOps Helper — Installed!${NC}"
echo -e "${BOLD}=========================================${NC}"
echo ""
echo "  Binary:   $HELPER_DEST"
echo "  Plist:    $PLIST_DEST"
echo "  Socket:   $SOCKET_PATH"
echo "  Logs:     $LOG_FILE"
echo ""
echo "  Status:   sudo launchctl print system/$HELPER_LABEL"
echo "  Logs:     tail -f $LOG_FILE"
echo "  Restart:  sudo launchctl kickstart -k system/$HELPER_LABEL"
echo "  Remove:   sudo bash $0 --uninstall"
echo ""
