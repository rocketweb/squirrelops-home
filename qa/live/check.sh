#!/usr/bin/env bash
#
# Group F: live-system functional checks.
#
# Read-only. Nothing here mutates the install, the database, PF, or the network.
# Checks needing root print the exact command to run instead of running it, so
# the script never asks for a password.
#
# Usage: bash qa/live/check.sh

set -uo pipefail

PASS=0
FAIL=0
SKIP=0

ok()   { printf "  PASS  %-6s %s\n" "$1" "$2"; PASS=$((PASS+1)); }
bad()  { printf "  FAIL  %-6s %s\n" "$1" "$2"; FAIL=$((FAIL+1)); }
skip() { printf "  SKIP  %-6s %s\n" "$1" "$2"; SKIP=$((SKIP+1)); }

# Run one command for a bounded interval using only tools present on stock
# macOS. GNU coreutils' `timeout` is not installed by default.
run_bounded() {
    local duration=$1
    shift
    "$@" &
    local command_pid=$!
    (
        sleep "$duration"
        kill -TERM "$command_pid" 2>/dev/null || true
    ) &
    local timer_pid=$!
    wait "$command_pid" 2>/dev/null || true
    kill -TERM "$timer_pid" 2>/dev/null || true
    wait "$timer_pid" 2>/dev/null || true
}

SENSOR_DIR=/Library/SquirrelOps/sensor
SENSOR_DB="$SENSOR_DIR/data/squirrelops.db"

echo "Group F: live system"
echo

# --- F-01 -------------------------------------------------------------------
proc_line=$(ps -axo user,command | grep '[s]quirrelops_home_sensor' | head -1)
if [ -n "$proc_line" ]; then
    owner=$(echo "$proc_line" | awk '{print $1}')
    if [ "$owner" = "_squirrelops" ]; then
        ok "F-01" "sensor running as _squirrelops"
    else
        bad "F-01" "sensor running as '$owner', expected _squirrelops"
    fi
else
    bad "F-01" "no sensor process found"
fi

# --- F-02 -------------------------------------------------------------------
for label in com.squirrelops.sensor com.squirrelops.helper; do
    if [ -f "/Library/LaunchDaemons/${label}.plist" ]; then
        ok "F-02" "$label plist installed"
    else
        bad "F-02" "$label plist missing"
    fi
done

# --- F-03 -------------------------------------------------------------------
code=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/system/status 2>/dev/null)
if [ "$code" = "403" ] || [ "$code" = "401" ]; then
    ok "F-03" "API answers on 8443 and demands a client certificate ($code)"
elif [ "$code" = "200" ]; then
    bad "F-03" "API answered 200 with no client certificate"
else
    bad "F-03" "unexpected response from 8443: '$code'"
fi

# --- F-04 -------------------------------------------------------------------
if [ -r "$SENSOR_DIR/VERSION" ] && [ -r "$SENSOR_DIR/release-components.json" ]; then
    installed=$(cat "$SENSOR_DIR/VERSION")
    declared=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["sensor_version"])' "$SENSOR_DIR/release-components.json" 2>/dev/null)
    if [ "$installed" = "$declared" ]; then
        ok "F-04" "sensor version $installed matches release-components.json"
    else
        bad "F-04" "VERSION '$installed' but release-components says '$declared'"
    fi
else
    skip "F-04" "version files unreadable"
fi

# --- F-05, F-06 -------------------------------------------------------------
aliases=$(ifconfig lo0 2>/dev/null | awk '/inet 192\.168\./ {print $2}' | sort)
alias_count=$(echo "$aliases" | grep -c . || true)
if [ -r "$SENSOR_DB" ]; then
    rows=$(sqlite3 "$SENSOR_DB" "SELECT DISTINCT bind_address FROM decoys WHERE retired_at IS NULL AND decoy_type='mimic' ORDER BY bind_address;" 2>/dev/null | sort)
    missing_row=$(comm -23 <(echo "$aliases") <(echo "$rows"))
    missing_alias=$(comm -13 <(echo "$aliases") <(echo "$rows"))
    [ -z "$missing_row" ] && ok "F-05" "every live alias has a decoy row" \
        || bad "F-05" "aliases with no live decoy row: $(echo $missing_row)"
    [ -z "$missing_alias" ] && ok "F-06" "every live mimic row has an alias" \
        || bad "F-06" "decoy rows with no alias: $(echo $missing_alias)"
else
    skip "F-05" "needs root: sudo sqlite3 $SENSOR_DB \"SELECT DISTINCT bind_address FROM decoys WHERE retired_at IS NULL AND decoy_type='mimic';\""
    skip "F-06" "same query as F-05"
fi
echo "        (observed $alias_count lo0 aliases: $(echo $aliases))"

# --- F-07 -------------------------------------------------------------------
adverts=$(run_bounded 6 dns-sd -B _squirrelops._tcp local. 2>/dev/null | grep -c 'Add' || true)
if [ "$adverts" -ge 1 ]; then
    ok "F-07" "_squirrelops._tcp advertised ($adverts records)"
else
    bad "F-07" "_squirrelops._tcp not advertised"
fi

# --- F-08 -------------------------------------------------------------------
if [ -n "$aliases" ]; then
    conflict=0
    # A mimic hostname must not resolve to more than one address.
    if [ -r "$SENSOR_DB" ]; then
        for host in $(sqlite3 "$SENSOR_DB" "SELECT DISTINCT hostname FROM decoy_hosts WHERE retired_at IS NULL;" 2>/dev/null); do
            n=$(run_bounded 4 dns-sd -G v4 "$host" 2>/dev/null | grep -c 'Add' || true)
            [ "$n" -gt 1 ] && conflict=1 && echo "        $host resolves to $n addresses"
        done
        [ "$conflict" -eq 0 ] && ok "F-08" "each mimic hostname resolves to one address" \
            || bad "F-08" "a mimic hostname resolves to several addresses"
    else
        skip "F-08" "needs root to read mimic hostnames from the DB"
    fi
else
    skip "F-08" "no aliases present"
fi

# --- F-09 -------------------------------------------------------------------
# arp -n emits unpadded octets (1c:1d:d3:e0:7d:3) while ifconfig pads them
# (1c:1d:d3:e0:7d:03). Both sides must be normalized or every address the Mac
# owns looks foreign. This is the same trap H-03 pins in normalize_mac.
normalize_mac() {
    echo "$1" | tr 'A-Z' 'a-z' | awk -F: '{
        out=""
        for (i = 1; i <= NF; i++) out = out (i > 1 ? ":" : "") sprintf("%02s", $i)
        print out
    }'
}

collision=0
own=$(for m in $(ifconfig 2>/dev/null | awk '/ether/ {print $2}'); do normalize_mac "$m"; done)
for ip in $aliases; do
    raw=$(arp -n "$ip" 2>/dev/null | awk '/at/ {print $4}')
    [ -z "$raw" ] && continue
    mac=$(normalize_mac "$raw")
    if ! echo "$own" | grep -qx "$mac"; then
        echo "        $ip answered by foreign MAC $mac"
        collision=1
    fi
done
[ "$collision" -eq 0 ] && ok "F-09" "no virtual IP is answered by a foreign host" \
    || bad "F-09" "a virtual IP collides with a real host"

# --- F-10, F-11 -------------------------------------------------------------
if [ -r "$SENSOR_DB" ]; then
    integrity=$(sqlite3 "$SENSOR_DB" "PRAGMA integrity_check;" 2>/dev/null)
    [ "$integrity" = "ok" ] && ok "F-10" "database integrity_check ok" \
        || bad "F-10" "integrity_check: $integrity"
    orphans=$(sqlite3 "$SENSOR_DB" "SELECT COUNT(*) FROM events WHERE event_type LIKE 'alert%' AND json_extract(payload,'\$.id') NOT IN (SELECT id FROM home_alerts);" 2>/dev/null)
    [ "${orphans:-0}" = "0" ] && ok "F-11" "no orphaned alert events" \
        || bad "F-11" "$orphans orphaned alert events"
else
    skip "F-10" "needs root: sudo sqlite3 $SENSOR_DB 'PRAGMA integrity_check;'"
    skip "F-11" "needs root: orphaned-event query, see qa/FUNCTIONAL-TEST-PLAN.md"
fi

# --- F-12 -------------------------------------------------------------------
sock=/var/run/squirrelops-helper.sock
if [ -e "$sock" ]; then
    perms=$(stat -f '%Su:%Sg:%Lp' "$sock")
    case "$perms" in
        root:*) ok "F-12" "helper socket owned by root ($perms)" ;;
        *)      bad "F-12" "helper socket owned by $perms" ;;
    esac
else
    bad "F-12" "helper socket missing at $sock"
fi

# --- F-13 -------------------------------------------------------------------
logdir="$SENSOR_DIR/logs"
if [ -d "$logdir" ]; then
    mode=$(stat -f '%Lp' "$logdir")
    # %Lp prints octal digits; bash arithmetic would read "700" as decimal.
    if [ "$((8#$mode & 4))" -eq 0 ]; then
        ok "F-13" "log directory is not world-readable (mode $mode)"
    else
        bad "F-13" "log directory is world-readable (mode $mode)"
    fi
else
    skip "F-13" "log directory not present"
fi

echo
echo "  $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
