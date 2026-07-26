#!/usr/bin/env bash
#
# SquirrelOps Home — Uninstall Script
#
# Removes the SquirrelOps Home app, sensor, and related files.
# Must be run with sudo.
#
# Usage:
#   sudo bash /Library/SquirrelOps/sensor/uninstall.sh
#   sudo bash /Library/SquirrelOps/sensor/uninstall.sh --preserve-data
#   sudo bash /Library/SquirrelOps/sensor/uninstall.sh --remove-data
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

parse_uninstall_options() {
    REMOVE_DATA_MODE="interactive"
    local option
    for option in "$@"; do
        case "$option" in
            --preserve-data)
                if [ "$REMOVE_DATA_MODE" != "interactive" ]; then
                    echo "The --preserve-data and --remove-data options are mutually exclusive and may be specified only once." >&2
                    return 2
                fi
                REMOVE_DATA_MODE="preserve"
                ;;
            --remove-data)
                if [ "$REMOVE_DATA_MODE" != "interactive" ]; then
                    echo "The --preserve-data and --remove-data options are mutually exclusive and may be specified only once." >&2
                    return 2
                fi
                REMOVE_DATA_MODE="remove"
                ;;
            *)
                echo "Unknown uninstall option: $option" >&2
                return 2
                ;;
        esac
    done
}

select_remove_data() {
    local user_state_present="$1"
    REMOVE_DATA="n"
    if [ "$user_state_present" -eq 0 ]; then
        # There is nothing user-owned to preserve. Treat this as full removal
        # so an interrupted first install cannot leave its service identity or
        # root-owned lifecycle markers behind.
        REMOVE_DATA="y"
        return 0
    fi
    case "$REMOVE_DATA_MODE" in
        preserve)
            return 0
            ;;
        remove)
            REMOVE_DATA="y"
            return 0
            ;;
        interactive)
            if [ "$user_state_present" -eq 1 ]; then
                echo ""
                echo -e "${YELLOW}Sensor state may contain your configuration, device database,"
                echo -e "alert history, logs, TLS certificates, and local pairing credentials.${NC}"
                echo ""
                # Read from /dev/tty to work even when piped.
                printf "  Remove sensor data and configuration? [y/N] "
                read -r REMOVE_DATA < /dev/tty || REMOVE_DATA="n"
                echo ""
            fi
            ;;
    esac
}

if parse_uninstall_options "$@"; then
    :
else
    option_status=$?
    exit "$option_status"
fi

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
HELPER_STATE_DIR="/var/db/com.squirrelops.helper"
HELPER_ALIAS_STATE="/var/db/com.squirrelops.helper/owned-aliases"
BACKUP_ROOT="/Library/SquirrelOps/backups"
SENSOR_USER="_squirrelops"
SENSOR_GROUP="_squirrelops"
STAGED_SENSOR_USER="_squirrelops_installing"
STAGED_SENSOR_GROUP="_squirrelops_installing"
ACCOUNT_PROVISIONING_DIR="/var/db/com.squirrelops.sensor"
ACCOUNT_PROVISIONING_MARKER="$ACCOUNT_PROVISIONING_DIR/account-provisioning"
ACCOUNT_DEPROVISIONING_MARKER="$ACCOUNT_PROVISIONING_DIR/account-deprovisioning"
SENSOR_UID=""
SENSOR_GID=""

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

directory_service_value() {
    local record="$1"
    local key="$2"
    /usr/bin/dscl . -read "$record" "$key" 2>/dev/null \
        | /usr/bin/awk \
            -v expected="${key}:" \
            -v native_hidden="dsAttrTypeNative:IsHidden:" '
            ($1 == expected \
                || (expected == "IsHidden:" && $1 == native_hidden)) \
                && NF == 2 {
                value = $2
                count++
            }
            END {
                if (count != 1) {
                    exit 1
                }
                print value
            }
        '
}

validate_service_identity() {
    local shell
    local home
    local hidden
    local uid_owner
    local gid_owner

    SENSOR_UID=$(directory_service_value \
        "/Users/${SENSOR_USER}" "UniqueID") || return 1
    SENSOR_GID=$(directory_service_value \
        "/Users/${SENSOR_USER}" "PrimaryGroupID") || return 1
    shell=$(directory_service_value \
        "/Users/${SENSOR_USER}" "UserShell") || return 1
    home=$(directory_service_value \
        "/Users/${SENSOR_USER}" "NFSHomeDirectory") || return 1
    hidden=$(directory_service_value \
        "/Users/${SENSOR_USER}" "IsHidden") || return 1
    [[ "$SENSOR_UID" =~ ^[0-9]+$ ]] \
        && [[ "$SENSOR_GID" =~ ^[0-9]+$ ]] \
        && [ "$SENSOR_UID" -ge 300 ] && [ "$SENSOR_UID" -le 499 ] \
        && [ "$SENSOR_GID" = "$SENSOR_UID" ] \
        && [ "$shell" = "/usr/bin/false" ] \
        && [ "$home" = "/var/empty" ] \
        && [ "$hidden" = "1" ] \
        || return 1
    [ "$(directory_service_value \
        "/Groups/${SENSOR_GROUP}" "PrimaryGroupID")" = "$SENSOR_GID" ] \
        || return 1
    uid_owner=$(
        /usr/bin/dscl . -list /Users UniqueID 2>/dev/null \
            | /usr/bin/awk -v id="$SENSOR_UID" '
                $2 == id { owner = $1; count++ }
                END { if (count == 1) print owner }
            '
    ) || return 1
    gid_owner=$(
        /usr/bin/dscl . -list /Groups PrimaryGroupID 2>/dev/null \
            | /usr/bin/awk -v id="$SENSOR_GID" '
                $2 == id { owner = $1; count++ }
                END { if (count == 1) print owner }
            '
    ) || return 1
    [ "$uid_owner" = "$SENSOR_USER" ] \
        && [ "$gid_owner" = "$SENSOR_GROUP" ]
}

sensor_processes_are_running() {
    /usr/bin/pgrep -u "$SENSOR_UID" '.*' >/dev/null 2>&1 \
        || /usr/bin/pgrep -U "$SENSOR_UID" '.*' >/dev/null 2>&1
}

terminate_sensor_processes() {
    local attempts=0
    /usr/bin/pkill -TERM -u "$SENSOR_UID" '.*' >/dev/null 2>&1 || true
    /usr/bin/pkill -TERM -U "$SENSOR_UID" '.*' >/dev/null 2>&1 || true
    while sensor_processes_are_running && [ "$attempts" -lt 5 ]; do
        sleep 1
        attempts=$((attempts + 1))
    done
    if sensor_processes_are_running; then
        /usr/bin/pkill -KILL -u "$SENSOR_UID" '.*' >/dev/null 2>&1 || true
        /usr/bin/pkill -KILL -U "$SENSOR_UID" '.*' >/dev/null 2>&1 || true
    fi
    attempts=0
    while sensor_processes_are_running && [ "$attempts" -lt 5 ]; do
        sleep 1
        attempts=$((attempts + 1))
    done
    ! sensor_processes_are_running
}

quiesce_sensor_identity() {
    if ! /usr/bin/dscl . -read "/Users/${SENSOR_USER}" >/dev/null 2>&1; then
        return 0
    fi
    if ! validate_service_identity; then
        return 1
    fi
    if /usr/bin/crontab -u "$SENSOR_USER" -l >/dev/null 2>&1; then
        /usr/bin/crontab -u "$SENSOR_USER" -r >/dev/null 2>&1 \
            || return 1
    fi
    ! /usr/bin/crontab -u "$SENSOR_USER" -l >/dev/null 2>&1 \
        && terminate_sensor_processes
}

read_account_provisioning_id() {
    local provisioned_id
    if [ -L "$ACCOUNT_PROVISIONING_DIR" ] \
        || [ ! -d "$ACCOUNT_PROVISIONING_DIR" ] \
        || [ "$(/usr/bin/stat -f '%Su:%Sg:%Lp' \
            "$ACCOUNT_PROVISIONING_DIR")" != "root:wheel:700" ] \
        || [ -L "$ACCOUNT_PROVISIONING_MARKER" ] \
        || [ ! -f "$ACCOUNT_PROVISIONING_MARKER" ] \
        || [ "$(/usr/bin/stat -f '%Su:%Sg:%Lp:%l:%z' \
            "$ACCOUNT_PROVISIONING_MARKER")" != "root:wheel:600:1:4" ]
    then
        return 1
    fi
    provisioned_id=$(/bin/cat "$ACCOUNT_PROVISIONING_MARKER") \
        || return 1
    [[ "$provisioned_id" =~ ^[0-9]{3}$ ]] \
        && [ "$provisioned_id" -ge 300 ] \
        && [ "$provisioned_id" -le 499 ] \
        || return 1
    printf '%s\n' "$provisioned_id"
}

read_account_deprovisioning_id() {
    local provisioned_id
    if [ -L "$ACCOUNT_PROVISIONING_DIR" ] \
        || [ ! -d "$ACCOUNT_PROVISIONING_DIR" ] \
        || [ "$(/usr/bin/stat -f '%Su:%Sg:%Lp' \
            "$ACCOUNT_PROVISIONING_DIR")" != "root:wheel:700" ] \
        || [ -L "$ACCOUNT_DEPROVISIONING_MARKER" ] \
        || [ ! -f "$ACCOUNT_DEPROVISIONING_MARKER" ] \
        || [ "$(/usr/bin/stat -f '%Su:%Sg:%Lp:%l:%z' \
            "$ACCOUNT_DEPROVISIONING_MARKER")" != "root:wheel:600:1:4" ]
    then
        return 1
    fi
    provisioned_id=$(/bin/cat "$ACCOUNT_DEPROVISIONING_MARKER") \
        || return 1
    [[ "$provisioned_id" =~ ^[0-9]{3}$ ]] \
        && [ "$provisioned_id" -ge 300 ] \
        && [ "$provisioned_id" -le 499 ] \
        || return 1
    printf '%s\n' "$provisioned_id"
}

write_account_deprovisioning_id() {
    local provisioned_id="$1"
    local marker_temp
    if [ -e "$ACCOUNT_PROVISIONING_MARKER" ] \
        || [ -L "$ACCOUNT_PROVISIONING_MARKER" ] \
        || [ -e "$ACCOUNT_DEPROVISIONING_MARKER" ] \
        || [ -L "$ACCOUNT_DEPROVISIONING_MARKER" ] \
        || [ -L "$ACCOUNT_PROVISIONING_DIR" ] \
        || { [ -e "$ACCOUNT_PROVISIONING_DIR" ] \
            && [ ! -d "$ACCOUNT_PROVISIONING_DIR" ]; }
    then
        return 1
    fi
    if ! /usr/bin/install -d -o root -g wheel -m 700 \
        "$ACCOUNT_PROVISIONING_DIR" \
        || [ "$(/usr/bin/stat -f '%Su:%Sg:%Lp' \
            "$ACCOUNT_PROVISIONING_DIR")" != "root:wheel:700" ]
    then
        return 1
    fi
    marker_temp=$(
        /usr/bin/mktemp \
            "$ACCOUNT_PROVISIONING_DIR/.account-deprovisioning.XXXXXXXX"
    ) || return 1
    if ! printf '%s\n' "$provisioned_id" > "$marker_temp" \
        || ! /usr/sbin/chown root:wheel "$marker_temp" \
        || ! /bin/chmod 600 "$marker_temp" \
        || ! /bin/mv -fh "$marker_temp" \
            "$ACCOUNT_DEPROVISIONING_MARKER" \
        || ! /bin/sync
    then
        return 1
    fi
    [ "$(read_account_deprovisioning_id)" = "$provisioned_id" ]
}

record_id_matches_or_is_unset() {
    local record="$1"
    local key="$2"
    local expected_id="$3"
    local actual_id
    if ! /usr/bin/dscl . -read "$record" >/dev/null 2>&1; then
        return 0
    fi
    if ! /usr/bin/dscl . -read "$record" "$key" >/dev/null 2>&1; then
        return 0
    fi
    actual_id=$(directory_service_value "$record" "$key") || return 1
    [ "$actual_id" = "$expected_id" ]
}

directory_service_text_value() {
    local record="$1"
    local key="$2"
    /usr/bin/dscl . -read "$record" "$key" 2>/dev/null \
        | /usr/bin/awk \
            -v expected="${key}:" \
            -v native_hidden="dsAttrTypeNative:IsHidden:" '
            $1 == expected \
                || (expected == "IsHidden:" && $1 == native_hidden) {
                $1 = ""
                sub(/^ /, "")
                value = $0
                count++
            }
            END {
                if (count != 1 || value == "") {
                    exit 1
                }
                print value
            }
        '
}

record_value_matches_or_is_missing() {
    local record="$1"
    local key="$2"
    local expected="$3"
    local actual
    if ! /usr/bin/dscl . -read "$record" "$key" >/dev/null 2>&1; then
        /usr/bin/dscl . -read "$record" >/dev/null 2>&1
        return
    fi
    actual=$(directory_service_text_value "$record" "$key") || return 1
    [ "$actual" = "$expected" ]
}

record_attribute_is_empty_or_missing() {
    local record="$1"
    local key="$2"
    local output
    if ! output=$(
        /usr/bin/dscl . -read "$record" "$key" 2>/dev/null
    ); then
        /usr/bin/dscl . -read "$record" >/dev/null 2>&1
        return
    fi
    printf '%s\n' "$output" \
        | /usr/bin/awk -v expected="${key}:" '
            $1 == expected && NF == 1 { seen++ ; next }
            NF != 0 { bad = 1 }
            END { exit !(seen == 1 && bad == 0) }
        '
}

deprovisioning_records_match_id() {
    local provisioned_id="$1"
    local conflicting_user
    local conflicting_group
    local user_present=0
    local group_present=0

    if /usr/bin/dscl . -read "/Users/${SENSOR_USER}" >/dev/null 2>&1; then
        user_present=1
    fi
    if /usr/bin/dscl . -read "/Groups/${SENSOR_GROUP}" >/dev/null 2>&1; then
        group_present=1
    fi
    if [ "$user_present" -eq 1 ]; then
        [ "$group_present" -eq 1 ] || return 1
        record_value_matches_or_is_missing \
            "/Users/${SENSOR_USER}" "RealName" "SquirrelOps Sensor" \
            && record_value_matches_or_is_missing \
                "/Users/${SENSOR_USER}" "UserShell" "/usr/bin/false" \
            && record_value_matches_or_is_missing \
                "/Users/${SENSOR_USER}" "UniqueID" "$provisioned_id" \
            && record_value_matches_or_is_missing \
                "/Users/${SENSOR_USER}" "PrimaryGroupID" "$provisioned_id" \
            && record_value_matches_or_is_missing \
                "/Users/${SENSOR_USER}" "NFSHomeDirectory" "/var/empty" \
            && record_value_matches_or_is_missing \
                "/Users/${SENSOR_USER}" "IsHidden" "1" \
            || return 1
    fi
    if [ "$group_present" -eq 1 ]; then
        [ "$(directory_service_value \
            "/Groups/${SENSOR_GROUP}" "PrimaryGroupID")" \
            = "$provisioned_id" ] \
            && record_attribute_is_empty_or_missing \
                "/Groups/${SENSOR_GROUP}" "GroupMembership" \
            && record_attribute_is_empty_or_missing \
                "/Groups/${SENSOR_GROUP}" "GroupMembers" \
            || return 1
    fi

    conflicting_user=$(
        /usr/bin/dscl . -list /Users UniqueID 2>/dev/null \
            | /usr/bin/awk \
                -v id="$provisioned_id" \
                -v final="$SENSOR_USER" \
                '$2 == id && $1 != final { print $1 }'
    ) || return 1
    conflicting_group=$(
        /usr/bin/dscl . -list /Groups PrimaryGroupID 2>/dev/null \
            | /usr/bin/awk \
                -v id="$provisioned_id" \
                -v final="$SENSOR_GROUP" \
                '$2 == id && $1 != final { print $1 }'
    ) || return 1
    [ -z "$conflicting_user" ] && [ -z "$conflicting_group" ]
}

retire_account_provisioning_dir() {
    if [ ! -e "$ACCOUNT_PROVISIONING_DIR" ] \
        && [ ! -L "$ACCOUNT_PROVISIONING_DIR" ]
    then
        return 0
    fi
    if [ -L "$ACCOUNT_PROVISIONING_DIR" ] \
        || [ ! -d "$ACCOUNT_PROVISIONING_DIR" ] \
        || [ "$(/usr/bin/stat -f '%Su:%Sg:%Lp' \
            "$ACCOUNT_PROVISIONING_DIR")" != "root:wheel:700" ]
    then
        return 1
    fi
    /usr/bin/find "$ACCOUNT_PROVISIONING_DIR" \
        -xdev -mindepth 1 -maxdepth 1 -print0 \
        | while IFS= read -r -d '' entry; do
            local name
            name=$(/usr/bin/basename "$entry") || return 1
            case "$name" in
                .account-provisioning.*|.account-deprovisioning.*) ;;
                *) return 1 ;;
            esac
            [ ! -L "$entry" ] \
                && [ "$(/usr/bin/stat -f '%Su:%Sg:%HT:%Lp:%l' "$entry")" \
                    = "root:wheel:Regular File:600:1" ] \
                || return 1
            rm -f -- "$entry" || return 1
        done \
        || return 1
    rmdir "$ACCOUNT_PROVISIONING_DIR" 2>/dev/null
}

retire_account_provisioning_marker() {
    rm -f -- "$ACCOUNT_PROVISIONING_MARKER" || return 1
    retire_account_provisioning_dir || return 1
    /bin/sync
}

cleanup_interrupted_account_deprovisioning() {
    local provisioned_id

    if [ ! -e "$ACCOUNT_DEPROVISIONING_MARKER" ] \
        && [ ! -L "$ACCOUNT_DEPROVISIONING_MARKER" ]
    then
        return 0
    fi
    [ ! -e "$ACCOUNT_PROVISIONING_MARKER" ] \
        && [ ! -L "$ACCOUNT_PROVISIONING_MARKER" ] \
        || return 1
    provisioned_id=$(read_account_deprovisioning_id) || return 1
    if /usr/bin/dscl . -read "/Users/${STAGED_SENSOR_USER}" \
            >/dev/null 2>&1 \
        || /usr/bin/dscl . -read "/Groups/${STAGED_SENSOR_GROUP}" \
            >/dev/null 2>&1 \
        || ! deprovisioning_records_match_id "$provisioned_id"
    then
        return 1
    fi

    SENSOR_UID="$provisioned_id"
    terminate_sensor_processes || return 1
    /usr/bin/crontab -u "$SENSOR_USER" -r >/dev/null 2>&1 || true
    if /usr/bin/dscl . -read "/Users/${SENSOR_USER}" >/dev/null 2>&1; then
        /usr/bin/dscl . -delete "/Users/${SENSOR_USER}" || return 1
    fi
    if /usr/bin/dscl . -read "/Groups/${SENSOR_GROUP}" >/dev/null 2>&1; then
        /usr/bin/dscl . -delete "/Groups/${SENSOR_GROUP}" || return 1
    fi
    ! /usr/bin/dscl . -read "/Users/${SENSOR_USER}" >/dev/null 2>&1 \
        && ! /usr/bin/dscl . -read "/Groups/${SENSOR_GROUP}" \
            >/dev/null 2>&1 \
        || return 1
    rm -f -- "$ACCOUNT_DEPROVISIONING_MARKER" || return 1
    retire_account_provisioning_dir || return 1
    /bin/sync
}

legacy_partial_account_id() {
    local provisioned_id
    [ ! -e "$ACCOUNT_PROVISIONING_MARKER" ] \
        && [ ! -L "$ACCOUNT_PROVISIONING_MARKER" ] \
        && [ ! -e "$ACCOUNT_DEPROVISIONING_MARKER" ] \
        && [ ! -L "$ACCOUNT_DEPROVISIONING_MARKER" ] \
        || return 1
    /usr/bin/dscl . -read "/Groups/${SENSOR_GROUP}" >/dev/null 2>&1 \
        || return 1
    provisioned_id=$(directory_service_value \
        "/Groups/${SENSOR_GROUP}" "PrimaryGroupID") || return 1
    [[ "$provisioned_id" =~ ^[0-9]{3}$ ]] \
        && [ "$provisioned_id" -ge 300 ] \
        && [ "$provisioned_id" -le 499 ] \
        && deprovisioning_records_match_id "$provisioned_id" \
        || return 1
    printf '%s\n' "$provisioned_id"
}

recover_legacy_partial_service_identity() {
    local provisioned_id
    if [ -e "$ACCOUNT_PROVISIONING_MARKER" ] \
        || [ -L "$ACCOUNT_PROVISIONING_MARKER" ] \
        || [ -e "$ACCOUNT_DEPROVISIONING_MARKER" ] \
        || [ -L "$ACCOUNT_DEPROVISIONING_MARKER" ]
    then
        return 0
    fi
    if ! /usr/bin/dscl . -read "/Users/${SENSOR_USER}" >/dev/null 2>&1 \
        && ! /usr/bin/dscl . -read "/Groups/${SENSOR_GROUP}" \
            >/dev/null 2>&1
    then
        return 0
    fi
    if validate_service_identity; then
        return 0
    fi
    provisioned_id=$(legacy_partial_account_id) || return 1
    write_account_deprovisioning_id "$provisioned_id" \
        && cleanup_interrupted_account_deprovisioning
}

cleanup_interrupted_account_provisioning() {
    local provisioned_id
    local conflicting_user
    local conflicting_group
    local record
    local staging_present=0

    for record in \
        "/Users/${STAGED_SENSOR_USER}" \
        "/Groups/${STAGED_SENSOR_GROUP}"
    do
        if /usr/bin/dscl . -read "$record" >/dev/null 2>&1; then
            staging_present=1
        fi
    done

    if [ ! -e "$ACCOUNT_PROVISIONING_MARKER" ] \
        && [ ! -L "$ACCOUNT_PROVISIONING_MARKER" ]
    then
        [ "$staging_present" -eq 0 ] || return 1
        if ! /usr/bin/dscl . -read "/Users/${SENSOR_USER}" \
                >/dev/null 2>&1 \
            && /usr/bin/dscl . -read "/Groups/${SENSOR_GROUP}" \
                >/dev/null 2>&1
        then
            return 1
        fi
        retire_account_provisioning_dir
        return
    fi
    provisioned_id=$(read_account_provisioning_id) || return 1

    if /usr/bin/dscl . -read "/Users/${SENSOR_USER}" >/dev/null 2>&1; then
        validate_service_identity \
            && [ "$SENSOR_UID" = "$provisioned_id" ] \
            && [ "$staging_present" -eq 0 ] \
            || return 1
        retire_account_provisioning_marker || return 1
        return
    fi

    record_id_matches_or_is_unset \
        "/Users/${STAGED_SENSOR_USER}" "UniqueID" "$provisioned_id" \
        && record_id_matches_or_is_unset \
            "/Users/${STAGED_SENSOR_USER}" "PrimaryGroupID" "$provisioned_id" \
        && record_id_matches_or_is_unset \
            "/Groups/${STAGED_SENSOR_GROUP}" "PrimaryGroupID" "$provisioned_id" \
        && record_id_matches_or_is_unset \
            "/Groups/${SENSOR_GROUP}" "PrimaryGroupID" "$provisioned_id" \
        || return 1
    conflicting_user=$(
        /usr/bin/dscl . -list /Users UniqueID 2>/dev/null \
            | /usr/bin/awk \
                -v id="$provisioned_id" \
                -v staged="$STAGED_SENSOR_USER" \
                '$2 == id && $1 != staged { print $1 }'
    ) || return 1
    conflicting_group=$(
        /usr/bin/dscl . -list /Groups PrimaryGroupID 2>/dev/null \
            | /usr/bin/awk \
                -v id="$provisioned_id" \
                -v staged="$STAGED_SENSOR_GROUP" \
                -v final="$SENSOR_GROUP" \
                '$2 == id && $1 != staged && $1 != final { print $1 }'
    ) || return 1
    [ -z "$conflicting_user" ] && [ -z "$conflicting_group" ] \
        || return 1

    SENSOR_UID="$provisioned_id"
    terminate_sensor_processes || return 1
    /usr/bin/crontab -u "$STAGED_SENSOR_USER" -r >/dev/null 2>&1 || true
    for record in \
        "/Users/${STAGED_SENSOR_USER}" \
        "/Groups/${STAGED_SENSOR_GROUP}" \
        "/Groups/${SENSOR_GROUP}"
    do
        if /usr/bin/dscl . -read "$record" >/dev/null 2>&1; then
            /usr/bin/dscl . -delete "$record" || return 1
        fi
    done
    retire_account_provisioning_marker || return 1
}

EXISTING_SENSOR_INSTALL=0
if [ -f "$PLIST_PATH" ] || [ -d "$INSTALL_DIR" ] \
    || service_is_loaded "$PLIST_NAME" || [ -d "$APP_PATH" ] \
    || [ -f "$HELPER_PLIST" ] || [ -f "$HELPER_BINARY" ] \
    || [ -e "$HELPER_SOCKET" ] \
    || [ -e "$HELPER_STATE_DIR" ] || [ -L "$HELPER_STATE_DIR" ] \
    || [ -e "$HELPER_ALIAS_STATE" ] || [ -L "$HELPER_ALIAS_STATE" ] \
    || service_is_loaded "$HELPER_LABEL"
then
    EXISTING_SENSOR_INSTALL=1
fi

recover_unmarked_legacy_identity_for_existing_install() {
    [ "$EXISTING_SENSOR_INSTALL" -eq 1 ] || return 0
    recover_legacy_partial_service_identity
}

echo ""
echo -e "${BOLD}SquirrelOps Home — Uninstaller${NC}"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Stop sensor service
# ---------------------------------------------------------------------------
if ! stop_service_and_verify "$PLIST_NAME" "sensor service"; then
    exit 1
fi
if ! cleanup_interrupted_account_deprovisioning \
    || ! recover_unmarked_legacy_identity_for_existing_install
then
    warn "Interrupted or legacy sensor account removal is unsafe; aborting uninstall."
    exit 1
fi
if ! quiesce_sensor_identity; then
    warn "Sensor service identity or detached processes are unsafe; aborting uninstall."
    exit 1
fi
if ! cleanup_interrupted_account_provisioning; then
    warn "Interrupted sensor account provisioning is unsafe; aborting uninstall."
    exit 1
fi
if ! stop_service_and_verify "$HELPER_LABEL" "privileged helper"; then
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 2: Remove stale virtual-network state and privileged helper
# ---------------------------------------------------------------------------
# A hard crash or interrupted upgrade can leave durable virtual-IP rows even
# though the sensor did not complete graceful cleanup.  Remove only validated
# aliases recorded by SquirrelOps.
remaining_aliases=0
state_was_loaded=0
virtual_ip_rows=""
helper_alias_rows=""
helper_state_was_loaded=0
helper_state_is_authoritative=0
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

    # A recorded interface may disappear between releases (for example, a USB
    # Ethernet adapter can be detached). In that case a scoped lookup cannot
    # succeed even though the scoped proxy entry disappeared with the
    # interface. Fall back to a bounded walk of the complete ARP table and fail
    # closed if enumeration fails, is unexpectedly large, or still contains an
    # exact published entry for this address.
    if ! /sbin/ifconfig "$interface" >/dev/null 2>&1; then
        global_proxy_arp_is_absent "$ip"
        return
    fi
    if output=$(/usr/sbin/arp -n -i "$interface" "$ip" 2>&1); then
        [[ "$output" != *published* && "$output" == *"($ip) at "* ]]
        return
    fi
    if ! /sbin/ifconfig "$interface" >/dev/null 2>&1; then
        global_proxy_arp_is_absent "$ip"
        return
    fi
    [[ "$output" != *published* && "$output" == *"-- no entry"* ]]
}

global_proxy_arp_is_absent() {
    local ip="$1"
    /usr/sbin/arp -an 2>/dev/null \
        | /usr/bin/awk -v exact="(${ip})" '
            NR > 16384 { exit 2 }
            index($0, exact) != 0 && $0 ~ /published/ { exit 1 }
        '
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

tracked_network_state_is_absent() {
    local tracked_ip
    local tracked_interface
    while IFS='|' read -r tracked_ip tracked_interface; do
        if [ -z "$tracked_ip" ] && [ -z "$tracked_interface" ]; then
            continue
        fi
        if has_ipv4_address lo0 "$tracked_ip" \
            || ! proxy_arp_is_absent "$tracked_interface" "$tracked_ip"
        then
            return 1
        fi
    done <<< "$virtual_ip_rows"
}

if [ -e "$HELPER_STATE_DIR" ] || [ -L "$HELPER_STATE_DIR" ]; then
    if [ -L "$HELPER_STATE_DIR" ] || [ ! -d "$HELPER_STATE_DIR" ]; then
        warn "Helper alias ownership directory has an unsafe file type; retaining PF and aborting."
        exit 1
    fi
    if [ "$(/usr/bin/stat -f '%Su:%Sg:%Lp' "$HELPER_STATE_DIR")" != "root:wheel:700" ]; then
        warn "Helper alias ownership directory has unsafe permissions; retaining PF and aborting."
        exit 1
    fi
    helper_state_is_authoritative=1
fi

if [ -e "$HELPER_ALIAS_STATE" ] || [ -L "$HELPER_ALIAS_STATE" ]; then
    if [ -L "$HELPER_ALIAS_STATE" ] || [ ! -f "$HELPER_ALIAS_STATE" ]; then
        warn "Helper alias ownership state has an unsafe file type; retaining PF and aborting."
        exit 1
    fi
    if [ "$(/usr/bin/stat -f '%Su:%Sg:%Lp' "$HELPER_ALIAS_STATE")" != "root:wheel:600" ]; then
        warn "Helper alias ownership state has unsafe permissions; retaining PF and aborting."
        exit 1
    fi
    if [ "$(/usr/bin/stat -f '%z' "$HELPER_ALIAS_STATE")" -gt 65536 ]; then
        warn "Helper alias ownership state is oversized; retaining PF and aborting."
        exit 1
    fi
    if ! helper_alias_rows=$(/bin/cat "$HELPER_ALIAS_STATE"); then
        warn "Cannot read helper alias ownership state; retaining PF and aborting."
        exit 1
    fi
    helper_state_was_loaded=1
fi

if [ "$helper_state_is_authoritative" -eq 1 ]; then
    # The validated permanent directory is the authority marker. An absent
    # ledger means no alias was ever claimed (for example, a crash after
    # block-only PF quarantine but before addIPAlias).
    # Package scripts never interpret the sensor-writable database as root.
    virtual_ip_rows="$helper_alias_rows"
    state_was_loaded=1
fi

squirrelops_pf_anchor_is_empty() {
    local filter_rules
    local translation_rules
    filter_rules=$(
        /sbin/pfctl -a com.apple/squirrelops -sr 2>/dev/null
    ) || return 1
    translation_rules=$(
        /sbin/pfctl -a com.apple/squirrelops -sn 2>/dev/null
    ) || return 1
    [ -z "$(printf '%s' "$filter_rules$translation_rules" \
        | /usr/bin/tr -d '[:space:]')" ]
}

legacy_network_state_is_safe() {
    local loopback_output
    local arp_output

    loopback_output=$(/sbin/ifconfig lo0 2>/dev/null) || return 1
    printf '%s\n' "$loopback_output" \
        | /usr/bin/awk '
            $1 == "inet" {
                split($2, octets, ".")
                if ($2 == "127.0.0.1" && $3 == "netmask" &&
                    tolower($4) == "0xff000000") {
                    required_loopback++
                }
                if (octets[1] != 127) {
                    unsafe_nonloopback_alias = 1
                }
            }
            END {
                exit !(required_loopback == 1 &&
                    !unsafe_nonloopback_alias)
            }
        ' \
        || return 1

    arp_output=$(/usr/sbin/arp -an 2>/dev/null) || return 1
    if printf '%s\n' "$arp_output" \
        | /usr/bin/awk '
            tolower($0) ~ /published/ { found = 1 }
            END { exit !found }
        '
    then
        return 1
    fi
    return 0
}

if [ "$state_was_loaded" -eq 0 ]; then
    if ! squirrelops_pf_anchor_is_empty; then
        warn "Cannot prove the SquirrelOps PF anchor is empty without durable alias state; retaining the existing installation."
        exit 1
    fi
    if ! legacy_network_state_is_safe; then
        warn "Legacy loopback or proxy-ARP state is unsafe; manual cleanup is required before uninstall."
        exit 1
    fi
fi

if [ "$state_was_loaded" -eq 1 ]; then
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

if ! quiesce_sensor_identity; then
    warn "Sensor UID process reappeared during network cleanup; aborting uninstall."
    exit 1
fi
if [ -e "$HELPER_ALIAS_STATE" ] || [ -L "$HELPER_ALIAS_STATE" ]; then
    if [ -L "$HELPER_ALIAS_STATE" ]; then
        warn "Helper alias ownership changed type during cleanup; aborting uninstall."
        exit 1
    fi
    if ! current_helper_alias_rows=$(/bin/cat "$HELPER_ALIAS_STATE"); then
        warn "Cannot re-read helper alias ownership after shutdown; aborting uninstall."
        exit 1
    fi
    if [ "$helper_state_was_loaded" -ne 1 ] \
        || [ "$current_helper_alias_rows" != "$helper_alias_rows" ]
    then
        warn "Helper alias ownership changed during cleanup; retaining helper state and aborting uninstall."
        exit 1
    fi
elif [ "$helper_state_was_loaded" -eq 1 ]; then
    warn "Helper alias ownership disappeared during cleanup; aborting uninstall."
    exit 1
fi
if ! /sbin/pfctl -a com.apple/squirrelops -F all >/dev/null 2>&1; then
    warn "PF anchor changed during helper shutdown; retaining helper artifacts and aborting uninstall."
    exit 1
fi
if ! tracked_network_state_is_absent; then
    warn "A tracked alias or proxy-ARP entry reappeared during helper shutdown; aborting uninstall."
    exit 1
fi
if ! rm -f -- "$HELPER_ALIAS_STATE" \
    || [ -e "$HELPER_ALIAS_STATE" ] || [ -L "$HELPER_ALIAS_STATE" ]
then
    warn "Could not retire verified helper alias ownership state."
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
# Rollback snapshots duplicate the full database, including local pairing
# credentials. They are installation artifacts, not the live state a user may
# intentionally retain for reinstall, so uninstall always removes them.
if [ -e "$BACKUP_ROOT" ] || [ -L "$BACKUP_ROOT" ]; then
    info "Removing secret-bearing upgrade snapshots..."
    if ! rm -rf -- "$BACKUP_ROOT" \
        || [ -e "$BACKUP_ROOT" ] || [ -L "$BACKUP_ROOT" ]
    then
        warn "Could not remove upgrade snapshots under $BACKUP_ROOT."
        exit 1
    fi
fi

DATA_DIR="$INSTALL_DIR/data"
USER_STATE_PRESENT=0
if [ -d "$DATA_DIR" ] || [ -f "$INSTALL_DIR/config.yaml" ] \
    || [ -f "$INSTALL_DIR/config.yaml.bak" ]
then
    USER_STATE_PRESENT=1
fi
select_remove_data "$USER_STATE_PRESENT"

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

# Remove the plist template now. Keep the uninstaller itself as the retry
# entrypoint until account teardown and helper-marker retirement both succeed.
rm -f "$INSTALL_DIR/com.squirrelops.sensor.plist"

# ---------------------------------------------------------------------------
# Step 6: Conditionally remove user state
# ---------------------------------------------------------------------------
if [[ "$REMOVE_DATA" =~ ^[Yy]$ ]]; then
    info "Removing sensor data and configuration..."
    rm -rf "$DATA_DIR"
    rm -rf "$INSTALL_DIR/logs"
    rm -f "$INSTALL_DIR/config.yaml"
    rm -f "$INSTALL_DIR/config.yaml.bak"
    if /usr/bin/dscl . -read "/Users/${SENSOR_USER}" \
            >/dev/null 2>&1
    then
        if ! validate_service_identity \
            || ! write_account_deprovisioning_id "$SENSOR_UID" \
            || ! cleanup_interrupted_account_deprovisioning
        then
            warn "Could not safely remove the sensor service identity."
            exit 1
        fi
    elif /usr/bin/dscl . -read "/Groups/${SENSOR_GROUP}" \
        >/dev/null 2>&1
    then
        warn "Unmarked sensor service-group state is unsafe."
        exit 1
    fi
    info "Sensor data and configuration removed."
else
    info "Keeping sensor data and configuration under $INSTALL_DIR"
fi

# The empty root-owned directory is the clean-uninstall marker when user data
# is preserved. It prevents stale sensor database rows from ever regaining
# privileged cleanup authority on reinstall. A full data removal retires it.
if [[ "$REMOVE_DATA" =~ ^[Yy]$ ]]; then
    if ! rm -rf -- "$HELPER_STATE_DIR" \
        || [ -e "$HELPER_STATE_DIR" ] || [ -L "$HELPER_STATE_DIR" ]
    then
        warn "Could not retire helper alias ownership state."
        exit 1
    fi
else
    if [ -L "$HELPER_STATE_DIR" ] \
        || { [ -e "$HELPER_STATE_DIR" ] && [ ! -d "$HELPER_STATE_DIR" ]; }
    then
        warn "Helper clean-uninstall marker has an unsafe file type."
        exit 1
    fi
    if ! /usr/bin/install -d -o root -g wheel -m 700 "$HELPER_STATE_DIR" \
        || [ "$(/usr/bin/stat -f '%Su:%Sg:%Lp' "$HELPER_STATE_DIR")" \
            != "root:wheel:700" ]
    then
        warn "Could not preserve the root-owned clean-uninstall marker."
        exit 1
    fi
fi

# Teardown is now retry-safe: only retire the on-disk uninstaller after all
# service-account and root-owned helper markers reached their terminal state.
rm -f "$INSTALL_DIR/uninstall.sh"
if [ -d "$INSTALL_DIR" ]; then
    rmdir "$INSTALL_DIR" 2>/dev/null || true
fi
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
