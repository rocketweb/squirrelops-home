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
HELPER_LABEL="com.squirrelops.helper"
HELPER_PLIST="/Library/LaunchDaemons/${HELPER_LABEL}.plist"
HELPER_BINARY="/Library/PrivilegedHelperTools/${HELPER_LABEL}"
HELPER_SOCKET="/var/run/squirrelops-helper.sock"

service_is_loaded() {
    local label="$1"
    launchctl print "system/${label}" >/dev/null 2>&1
}

stop_service_and_verify() {
    local label="$1"
    local description="$2"
    local attempts=0

    if ! service_is_loaded "$label"; then
        return 0
    fi

    info "Stopping ${description}..."
    if ! launchctl bootout "system/${label}" 2>/dev/null; then
        if service_is_loaded "$label"; then
            warn "Cannot stop ${description}; aborting uninstall."
            return 1
        fi
    fi

    while service_is_loaded "$label"; do
        if [ "$attempts" -ge 10 ]; then
            warn "${description} shutdown could not be verified; aborting uninstall."
            return 1
        fi
        sleep 1
        attempts=$((attempts + 1))
    done
    info "${description} stopped."
}

EXISTING_SENSOR_INSTALL=0
if [ -f "$PLIST_PATH" ] || [ -d "$INSTALL_DIR" ] \
    || service_is_loaded "$PLIST_NAME" || [ -d "$APP_PATH" ] \
    || [ -f "$HELPER_PLIST" ] || [ -f "$HELPER_BINARY" ] \
    || [ -e "$HELPER_SOCKET" ] || service_is_loaded "$HELPER_LABEL"
then
    EXISTING_SENSOR_INSTALL=1
fi

echo ""
echo -e "${BOLD}SquirrelOps Home — Uninstaller${NC}"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Stop sensor service
# ---------------------------------------------------------------------------
if ! stop_service_and_verify "$PLIST_NAME" "sensor service"; then
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 2: Remove stale virtual-network state and privileged helper
# ---------------------------------------------------------------------------
# A hard crash or interrupted upgrade can leave durable virtual-IP rows even
# though the sensor did not complete graceful cleanup.  Remove only validated
# aliases recorded by SquirrelOps.
DB_FILE="$INSTALL_DIR/data/squirrelops.db"
remaining_aliases=0
is_valid_ipv4() {
    local ip="$1"
    local -a octets
    local octet
    IFS='.' read -r -a octets <<< "$ip"
    [ "${#octets[@]}" -eq 4 ] || return 1
    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^[0-9]{1,3}$ ]] || return 1
        [ "$((10#$octet))" -le 255 ] || return 1
    done
}

has_ipv4_address() {
    local interface="$1"
    local ip="$2"
    /sbin/ifconfig "$interface" 2>/dev/null \
        | /usr/bin/awk -v ip="$ip" \
            '$1 == "inet" && $2 == ip { found = 1 } END { exit !found }'
}

has_loopback_host_alias() {
    local ip="$1"
    /sbin/ifconfig lo0 2>/dev/null \
        | /usr/bin/awk -v ip="$ip" \
            '$1 == "inet" && $2 == ip && $3 == "netmask" \
             && tolower($4) == "0xffffffff" { found = 1 } \
             END { exit !found }'
}

proxy_arp_is_absent() {
    local interface="$1"
    local ip="$2"
    local output
    if output=$(/usr/sbin/arp -n -i "$interface" "$ip" 2>&1); then
        [[ "$output" != *published* && "$output" == *"($ip) at "* ]]
        return
    fi
    [[ "$output" != *published* && "$output" == *"-- no entry"* ]]
}

LOCAL_INTERFACES=()
physical_interface_for_ipv4() {
    local ip="$1"
    local candidate
    for candidate in "${LOCAL_INTERFACES[@]}"; do
        [ "$candidate" = "lo0" ] && continue
        if has_ipv4_address "$candidate" "$ip"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

if [ "$EXISTING_SENSOR_INSTALL" -eq 1 ] && [ ! -f "$DB_FILE" ]; then
    warn "Cannot verify virtual-IP state for an existing installation; retaining PF and aborting."
    warn "Restore the sensor database or manually verify all aliases and proxy ARP entries before retrying."
    exit 1
fi

if [ -f "$DB_FILE" ]; then
    if ! local_interface_list=$(/sbin/ifconfig -l 2>/dev/null); then
        warn "Cannot enumerate local interfaces; retaining PF and aborting."
        exit 1
    fi
    read -r -a LOCAL_INTERFACES <<< "$local_interface_list"
    if [ "${#LOCAL_INTERFACES[@]}" -eq 0 ]; then
        warn "No local interfaces were reported; retaining PF and aborting."
        exit 1
    fi
    loopback_was_listed=0
    for local_interface in "${LOCAL_INTERFACES[@]}"; do
        if [ "$local_interface" = "lo0" ]; then
            loopback_was_listed=1
        fi
        if ! /sbin/ifconfig "$local_interface" >/dev/null 2>&1; then
            warn "Cannot inspect interface ${local_interface}; retaining PF and aborting."
            exit 1
        fi
    done
    if [ "$loopback_was_listed" -ne 1 ]; then
        warn "Cannot verify the loopback interface; retaining PF and aborting."
        exit 1
    fi
    if [ ! -x /usr/bin/sqlite3 ]; then
        warn "sqlite3 is unavailable; retaining PF and aborting."
        exit 1
    fi
    if ! database_check=$(
        /usr/bin/sqlite3 "$DB_FILE" "PRAGMA quick_check;"
    ); then
        warn "Cannot validate the sensor database; retaining PF and aborting."
        exit 1
    fi
    if [ "$database_check" != "ok" ]; then
        warn "Sensor database integrity check failed; retaining PF and aborting."
        exit 1
    fi
    if ! virtual_ip_rows=$(
        /usr/bin/sqlite3 -separator '|' "$DB_FILE" \
            "SELECT DISTINCT ip_address, interface FROM virtual_ips WHERE released_at IS NULL;"
    ); then
        warn "Cannot read recorded virtual IPs; retaining PF and aborting."
        exit 1
    fi
    while IFS='|' read -r virtual_ip virtual_interface; do
        # An empty result is represented by one empty here-string iteration.
        if [ -z "$virtual_ip" ] && [ -z "$virtual_interface" ]; then
            continue
        fi
        if ! is_valid_ipv4 "$virtual_ip" \
            || [[ ! "$virtual_interface" =~ ^[[:alnum:]]+$ ]]; then
            warn "Invalid virtual-IP state row; retaining PF and aborting."
            remaining_aliases=1
            continue
        fi

        if physical_interface=$(
            physical_interface_for_ipv4 "$virtual_ip"
        ); then
            warn "Tracked virtual IP is assigned to physical interface ${physical_interface}: ${virtual_ip}."
            warn "Manual cleanup is required before continuing; automatic physical-address removal is unsafe."
            remaining_aliases=1
            continue
        fi

        has_tracked_loopback_alias=0
        if has_loopback_host_alias "$virtual_ip"; then
            has_tracked_loopback_alias=1
        elif has_ipv4_address lo0 "$virtual_ip"; then
            warn "Refusing to remove non-/32 lo0 address $virtual_ip; retaining PF."
            warn "Manual cleanup is required before continuing."
            remaining_aliases=1
            continue
        fi

        if [ "$has_tracked_loopback_alias" -eq 1 ]; then
            /usr/sbin/arp -d "$virtual_ip" pub ifscope "$virtual_interface" \
                >/dev/null 2>&1 || true
            if ! proxy_arp_is_absent "$virtual_interface" "$virtual_ip"; then
                warn "Proxy ARP for $virtual_ip is still published; retaining PF."
                remaining_aliases=1
                continue
            fi

            if ! /sbin/ifconfig lo0 inet "$virtual_ip" -alias \
                >/dev/null 2>&1
            then
                warn "Could not remove tracked lo0 /32 alias $virtual_ip; retaining PF."
                remaining_aliases=1
                continue
            fi

            if has_ipv4_address lo0 "$virtual_ip" \
                || ! proxy_arp_is_absent "$virtual_interface" "$virtual_ip"
            then
                warn "Virtual IP $virtual_ip cleanup could not be verified; retaining PF."
                remaining_aliases=1
            fi
        elif ! proxy_arp_is_absent "$virtual_interface" "$virtual_ip"; then
            warn "Proxy ARP exists without a matching lo0 /32 alias for $virtual_ip."
            warn "Manual cleanup is required before continuing; automatic proxy-ARP deletion is unsafe."
            remaining_aliases=1
        fi
    done <<< "$virtual_ip_rows"
fi

if [ "$remaining_aliases" -ne 0 ]; then
    warn "Refusing to continue while a protected virtual IP remains."
    exit 1
fi

if ! /sbin/pfctl -a com.apple/squirrelops -F all >/dev/null 2>&1; then
    warn "PF anchor cleanup failed; retaining the helper and aborting uninstall."
    exit 1
fi

if ! stop_service_and_verify "$HELPER_LABEL" "privileged helper"; then
    exit 1
fi
rm -f "$HELPER_PLIST" "$HELPER_BINARY" "$HELPER_SOCKET"

# ---------------------------------------------------------------------------
# Step 3: Remove app from /Applications
# ---------------------------------------------------------------------------
if [ -d "$APP_PATH" ]; then
    info "Removing $APP_PATH..."
    rm -rf "$APP_PATH"
    info "App removed."
else
    info "App not found at $APP_PATH (already removed or installed elsewhere)."
fi

# ---------------------------------------------------------------------------
# Step 4: Ask whether to remove data
# ---------------------------------------------------------------------------
REMOVE_DATA="n"
DATA_DIR="$INSTALL_DIR/data"

if [ -d "$DATA_DIR" ] || [ -f "$INSTALL_DIR/config.yaml" ] \
    || [ -f "$INSTALL_DIR/config.yaml.bak" ]
then
    echo ""
    echo -e "${YELLOW}Sensor state may contain your configuration, device database,"
    echo -e "alert history, logs, and TLS certificates.${NC}"
    echo ""
    # Read from /dev/tty to work even when piped
    printf "  Remove sensor data and configuration? [y/N] "
    read -r REMOVE_DATA < /dev/tty || REMOVE_DATA="n"
    echo ""
fi

# ---------------------------------------------------------------------------
# Step 5: Remove sensor runtime and plist
# ---------------------------------------------------------------------------
info "Removing sensor runtime..."
rm -rf "$INSTALL_DIR/python" "$INSTALL_DIR/venv"
rm -rf "$INSTALL_DIR/run" "$INSTALL_DIR/signatures"
rm -f "$INSTALL_DIR/.python-mode" "$INSTALL_DIR/VERSION"

if [ -f "$PLIST_PATH" ]; then
    info "Removing launchd plist..."
    rm -f "$PLIST_PATH"
fi

# Remove the plist template and uninstall script from install dir
rm -f "$INSTALL_DIR/com.squirrelops.sensor.plist"
rm -f "$INSTALL_DIR/uninstall.sh"

# ---------------------------------------------------------------------------
# Step 6: Conditionally remove user state
# ---------------------------------------------------------------------------
if [[ "$REMOVE_DATA" =~ ^[Yy]$ ]]; then
    info "Removing sensor data and configuration..."
    rm -rf "$DATA_DIR"
    rm -rf "$INSTALL_DIR/logs"
    rm -f "$INSTALL_DIR/config.yaml"
    rm -f "$INSTALL_DIR/config.yaml.bak"
    if dscl . -read /Users/_squirrelops >/dev/null 2>&1; then
        if ! dscl . -delete /Users/_squirrelops >/dev/null 2>&1 \
            || dscl . -read /Users/_squirrelops >/dev/null 2>&1
        then
            warn "Could not remove the _squirrelops service account."
            exit 1
        fi
    fi
    if dscl . -read /Groups/_squirrelops >/dev/null 2>&1; then
        if ! dscl . -delete /Groups/_squirrelops >/dev/null 2>&1 \
            || dscl . -read /Groups/_squirrelops >/dev/null 2>&1
        then
            warn "Could not remove the _squirrelops service group."
            exit 1
        fi
    fi
    info "Sensor data and configuration removed."
else
    info "Keeping sensor data and configuration under $INSTALL_DIR"
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
# Step 7: Forget package receipts
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
if [ -d "$DATA_DIR" ] || [ -d "$INSTALL_DIR/logs" ] \
    || [ -f "$INSTALL_DIR/config.yaml" ] \
    || [ -f "$INSTALL_DIR/config.yaml.bak" ]
then
    info "Application, services, helper, and sensor runtime removed."
    warn "Sensor data and configuration were preserved under $INSTALL_DIR"
    warn "The _squirrelops account and group were retained with that state."
else
    info "All SquirrelOps Home components have been removed."
fi
echo ""
