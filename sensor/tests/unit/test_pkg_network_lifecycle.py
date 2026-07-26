"""Regression tests for macOS virtual-network install and removal ordering."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from squirrelops_home_sensor.profiles import PROFILE_SETTINGS, ResourceProfile

REPO_ROOT = Path(__file__).resolve().parents[3]
pytestmark = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="macOS package lifecycle tests require BSD system utilities",
)


def _shell_function(source: str, name: str) -> str:
    start = source.index(f"{name}() {{")
    end = source.index("\n}\n", start) + 3
    return source[start:end]


def test_app_upgrade_stops_sensor_before_privileged_helper() -> None:
    script = (REPO_ROOT / "scripts/pkg/app-scripts/preinstall").read_text()

    verify_service = script.index('launchctl print "system/${label}"')
    bootout_service = script.index('launchctl bootout "system/${label}"')
    stop_sensor = script.index(
        'stop_service_and_verify "$SENSOR_LABEL" "sensor daemon"'
    )
    validate_ledger = script.index(
        "Helper alias ownership state has unsafe permissions"
    )
    missing_state = script.index(
        "Cannot prove the SquirrelOps PF anchor is empty"
    )
    invalid_row = script.index("Invalid virtual-IP state row")
    reject_physical = script.index(
        "Tracked virtual IP is assigned to physical interface"
    )
    require_proxy_absent = script.index(
        "Proxy ARP exists without a matching lo0 /32 alias"
    )
    remove_alias = script.index('/sbin/ifconfig lo0 inet "$virtual_ip" -alias')
    verify_alias = script.index('if has_loopback_host_alias "$virtual_ip"; then')
    verify_proxy_absent = script.index(
        'if ! proxy_arp_is_absent "$virtual_interface" "$virtual_ip"; then'
    )
    abort_on_alias = script.index('if [ "$remaining_aliases" -ne 0 ]; then')
    clear_pf = script.index("/sbin/pfctl -a com.apple/squirrelops -F all")
    stop_helper = script.index(
        'stop_service_and_verify "$HELPER_LABEL" "privileged helper daemon"'
    )
    retire_ledger = script.index('rm -f -- "$HELPER_ALIAS_STATE"')
    remove_app = script.index('rm -rf "$APP_PATH"')

    assert (
        verify_service
        < bootout_service
        < stop_sensor
        < stop_helper
        < validate_ledger
        < missing_state
        < invalid_row
        < reject_physical
        < verify_alias
        < verify_proxy_absent
        < remove_alias
        < require_proxy_absent
        < abort_on_alias
        < clear_pf
        < retire_ledger
        < remove_app
    )
    assert 'while service_is_loaded "$label"; do' in script
    assert 'launchctl bootout "system/${label}" 2>/dev/null || true' not in script
    assert (
        '/sbin/pfctl -a com.apple/squirrelops -F all >/dev/null 2>&1 || true'
        not in script
    )
    assert '/sbin/ifconfig "$virtual_interface" inet "$virtual_ip" -alias' not in script
    assert "primary_ipv4_address()" not in script


def test_uninstaller_fails_closed_before_removing_helper_artifacts() -> None:
    script = (REPO_ROOT / "scripts/pkg/uninstall.sh").read_text()

    stop_sensor = script.index(
        'stop_service_and_verify "$PLIST_NAME" "sensor service"'
    )
    validate_ledger = script.index(
        "Helper alias ownership state has unsafe permissions"
    )
    missing_state = script.index(
        "Cannot prove the SquirrelOps PF anchor is empty"
    )
    invalid_state = script.index("Invalid virtual-IP state row")
    reject_physical = script.index(
        "Tracked virtual IP is assigned to physical interface"
    )
    assert "/usr/sbin/arp -d" in script
    assert '/sbin/ifconfig lo0 inet "$virtual_ip" -alias' in script
    assert 'tolower($4) == "0xffffffff"' in script
    assert 'if ! proxy_arp_is_absent "$virtual_interface" "$virtual_ip"; then' in script
    assert 'if [ "$remaining_aliases" -ne 0 ]; then' in script
    flush_pf = script.index(
        "if ! /sbin/pfctl -a com.apple/squirrelops -F all"
    )
    stop_helper = script.index(
        'stop_service_and_verify "$HELPER_LABEL" "privileged helper"'
    )
    remove_helper = script.index(
        'rm -f "$HELPER_PLIST" "$HELPER_BINARY" "$HELPER_SOCKET"'
    )
    retire_ledger = script.index('rm -rf -- "$HELPER_STATE_DIR"')
    assert (
        stop_sensor
        < stop_helper
        < validate_ledger
        < missing_state
        < invalid_state
        < reject_physical
        < flush_pf
        < remove_helper
        < retire_ledger
    )
    assert 'launchctl bootout system "$PLIST_PATH" 2>/dev/null || true' not in script
    assert 'launchctl bootout system "$HELPER_PLIST" 2>/dev/null || true' not in script
    assert '/sbin/pfctl -a com.apple/squirrelops -F all >/dev/null 2>&1 || true' not in script
    assert '/sbin/ifconfig "$virtual_interface" inet "$virtual_ip" -alias' not in script
    assert "primary_ipv4_address()" not in script
    assert '/usr/bin/dscl . -delete "/Users/${SENSOR_USER}"' in script
    assert '/usr/bin/dscl . -delete "/Groups/${SENSOR_GROUP}"' in script
    assert 'write_account_deprovisioning_id "$SENSOR_UID"' in script


def test_uninstaller_validates_helper_ledger_network_arguments() -> None:
    script = (REPO_ROOT / "scripts/pkg/uninstall.sh").read_text()

    assert 'virtual_ip_rows="$helper_alias_rows"' in script
    assert 'is_valid_ipv4 "$virtual_ip"' in script
    assert '"$((10#$octet))" -le 255' in script
    assert '[[ ! "$virtual_interface" =~ ^[[:alnum:]]+$ ]]' in script
    assert "Invalid virtual-IP state row" in script
    assert "remaining_aliases=1" in script


def test_package_cleanup_targets_only_root_owned_host_aliases() -> None:
    for relative_path in (
        "scripts/pkg/app-scripts/preinstall",
        "scripts/pkg/uninstall.sh",
    ):
        script = (REPO_ROOT / relative_path).read_text()
        assert "/usr/bin/sqlite3" not in script
        assert "squirrelops.db" not in script
        assert 'virtual_ip_rows="$helper_alias_rows"' in script
        assert 'has_loopback_host_alias "$virtual_ip"' in script
        assert 'tolower($4) == "0xffffffff"' in script
        assert 'physical_interface_for_ipv4 "$virtual_ip"' in script
        assert "Tracked virtual IP is assigned to physical interface" in script
        assert "Manual cleanup is required before continuing" in script
        assert 'if ! proxy_arp_is_absent "$virtual_interface" "$virtual_ip"; then' in script
        assert "Proxy ARP exists without a matching lo0 /32 alias" in script
        assert '/sbin/ifconfig "$virtual_interface" inet "$virtual_ip" -alias' not in script


def test_missing_recorded_interface_uses_bounded_global_proxy_arp_proof() -> None:
    for relative_path in (
        "scripts/pkg/app-scripts/preinstall",
        "scripts/pkg/uninstall.sh",
    ):
        script = (REPO_ROOT / relative_path).read_text()
        functions = "\n".join(
            (
                _shell_function(script, "global_proxy_arp_is_absent"),
                _shell_function(script, "proxy_arp_is_absent"),
            )
        )
        functions = (
            functions.replace("/sbin/ifconfig", "mock_ifconfig")
            .replace("/usr/sbin/arp", "mock_arp")
        )
        harness = f"""
set -o pipefail
INTERFACE_EXISTS="$1"
GLOBAL_OUTPUT="$2"
FAIL_GLOBAL="$3"
mock_ifconfig() {{
    [ "$INTERFACE_EXISTS" = "1" ]
}}
mock_arp() {{
    if [ "$1" = "-an" ]; then
        [ "$FAIL_GLOBAL" = "0" ] || return 1
        printf '%s' "$GLOBAL_OUTPUT"
        return 0
    fi
    return 1
}}
{functions}
proxy_arp_is_absent en9 192.168.50.12
"""

        def check(
            output: str,
            *,
            interface_exists: bool = False,
            fail_global: bool = False,
            shell_harness: str = harness,
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    shell_harness,
                    "proxy-arp-fallback",
                    "1" if interface_exists else "0",
                    output,
                    "1" if fail_global else "0",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        assert check("").returncode == 0
        assert (
            check(
                "? (192.168.50.13) at aa:bb:cc:dd:ee:ff "
                "on en0 ifscope published\n"
            ).returncode
            == 0
        )
        assert (
            check(
                "? (192.168.50.12) at aa:bb:cc:dd:ee:ff "
                "on en0 ifscope permanent published (proxy only)\n"
            ).returncode
            != 0
        )
        assert check("", fail_global=True).returncode != 0
        assert "NR > 16384 { exit 2 }" in functions


def test_sensor_preinstall_verifies_stop_then_retires_old_runtime() -> None:
    script = (REPO_ROOT / "scripts/pkg/preinstall").read_text()

    stop_service = script.index(
        'stop_service_and_verify "$PLIST_NAME" "sensor service"'
    )
    backup_data = script.index("if ! create_upgrade_snapshot; then")
    backup_config = script.index('cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"')
    retire_runtime = script.index('rm -rf "$INSTALL_DIR/python" "$INSTALL_DIR/venv"')
    remove_markers = script.index(
        'rm -f "$INSTALL_DIR/.python-mode" "$INSTALL_DIR/VERSION"'
    )

    assert (
        stop_service
        < backup_data
        < backup_config
        < retire_runtime
        < remove_markers
    )
    assert 'launchctl bootout system "$PLIST_PATH" 2>/dev/null || true' not in script


def test_sensor_preinstall_creates_verified_private_rollback_snapshot() -> None:
    script = (REPO_ROOT / "scripts/pkg/preinstall").read_text()

    assert 'BACKUP_ROOT="/Library/SquirrelOps/backups"' in script
    assert '/usr/bin/mktemp -d "$BACKUP_ROOT/preinstall.XXXXXXXX"' in script
    assert '/usr/bin/ditto "$DATA_DIR" "$backup_dir/data"' in script
    assert "/usr/bin/sqlite3 -bail -batch -nofollow -readonly" in script
    assert "PRAGMA trusted_schema=OFF; PRAGMA quick_check(1);" in script
    assert '".backup \'$backup_dir/data/squirrelops.db\'"' in script
    assert (
        '"$backup_dir/data/squirrelops.db" \\\n'
        '                "PRAGMA trusted_schema=OFF; PRAGMA quick_check(1);"'
        in script
    )
    assert 'cp -p "$CONFIG_FILE" "$backup_dir/config.yaml"' in script
    assert 'chmod -R go-rwx "$backup_dir"' in script
    assert '"$backup_dir/COMPLETE"' in script


def test_sensor_preinstall_prunes_old_verified_upgrade_snapshots() -> None:
    script = (REPO_ROOT / "scripts/pkg/preinstall").read_text()

    assert "UPGRADE_SNAPSHOTS_TO_KEEP=3" in script
    assert "prune_upgrade_snapshots()" in script
    assert '[ ! -f "$snapshot/COMPLETE" ]' in script
    assert 'rm -rf -- "$snapshot"' in script
    prune_call = script.index("if ! prune_upgrade_snapshots; then")
    assert script.index('"$backup_dir/COMPLETE"') < prune_call


def test_missing_live_database_uses_helper_owned_alias_ledger_for_recovery() -> None:
    for relative_path in (
        "scripts/pkg/app-scripts/preinstall",
        "scripts/pkg/uninstall.sh",
    ):
        script = (REPO_ROOT / relative_path).read_text()

        assert 'HELPER_ALIAS_STATE="/var/db/com.squirrelops.helper/owned-aliases"' in script
        assert (
            'if [ -e "$HELPER_ALIAS_STATE" ] '
            '|| [ -L "$HELPER_ALIAS_STATE" ]; then'
        ) in script
        assert 'virtual_ip_rows="$helper_alias_rows"' in script
        assert (
            'virtual_ip_rows="${virtual_ip_rows}'
            "${virtual_ip_rows:+$'\\n'}${helper_alias_rows}\""
            not in script
        )
        assert "Cannot verify virtual-IP state for an existing installation" not in script
        assert "Cannot prove the SquirrelOps PF anchor is empty" in script


def test_preledger_install_fails_closed_without_root_owned_alias_state() -> None:
    for relative_path in (
        "scripts/pkg/app-scripts/preinstall",
        "scripts/pkg/uninstall.sh",
    ):
        script = (REPO_ROOT / relative_path).read_text()

        assert "/usr/bin/sqlite3" not in script
        assert "legacy_cleanup_is_authorized" not in script
        anchor_check = _shell_function(
            script,
            "squirrelops_pf_anchor_is_empty",
        )
        assert "/sbin/pfctl -a com.apple/squirrelops -sr" in anchor_check
        assert "/sbin/pfctl -a com.apple/squirrelops -sn" in anchor_check
        missing_state = script.index(
            'if [ "$state_was_loaded" -eq 0 ]; then'
        )
        inspect_pf = script.index(
            "if ! squirrelops_pf_anchor_is_empty; then",
            missing_state,
        )
        reject_nonempty = script.index(
            "Cannot prove the SquirrelOps PF anchor is empty without durable alias state",
            inspect_pf,
        )
        assert missing_state < inspect_pf < reject_nonempty


def test_preledger_cleanup_rejects_rdr_only_pf_anchor() -> None:
    for relative_path in (
        "scripts/pkg/app-scripts/preinstall",
        "scripts/pkg/uninstall.sh",
    ):
        script = (REPO_ROOT / relative_path).read_text()
        anchor_check = _shell_function(
            script,
            "squirrelops_pf_anchor_is_empty",
        ).replace("/sbin/pfctl", "mock_pfctl")
        harness = f"""
FILTER_RULES="$1"
TRANSLATION_RULES="$2"
FAIL_QUERY="$3"
mock_pfctl() {{
    query="${{@:$#}}"
    if [ "$query" = "$FAIL_QUERY" ]; then
        return 1
    fi
    case "$query" in
        -sr) printf '%s' "$FILTER_RULES" ;;
        -sn) printf '%s' "$TRANSLATION_RULES" ;;
        *) return 1 ;;
    esac
}}
{anchor_check}
squirrelops_pf_anchor_is_empty
"""

        def check(
            filter_rules: str,
            translation_rules: str,
            fail_query: str = "none",
            shell_harness: str = harness,
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    shell_harness,
                    "pf-anchor-check",
                    filter_rules,
                    translation_rules,
                    fail_query,
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        assert check("", "").returncode == 0
        assert check("block drop all\n", "").returncode != 0
        assert (
            check(
                "",
                "rdr pass on en0 inet proto tcp to 192.168.1.200 "
                "port 80 -> 192.168.1.200 port 10080\n",
            ).returncode
            != 0
        )
        assert check("", "", "-sr").returncode != 0
        assert check("", "", "-sn").returncode != 0


def test_legacy_cleanup_rejects_orphaned_alias_and_proxy_state() -> None:
    safe_loopback = """
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
    inet 127.0.0.1 netmask 0xff000000
"""
    for relative_path in (
        "scripts/pkg/app-scripts/preinstall",
        "scripts/pkg/uninstall.sh",
    ):
        script = (REPO_ROOT / relative_path).read_text()
        functions = "\n".join(
            (
                _shell_function(script, "is_valid_ipv4"),
                _shell_function(script, "legacy_network_state_is_safe"),
            )
        )
        functions = (
            functions.replace("/sbin/ifconfig", "mock_ifconfig")
            .replace("/sbin/route", "mock_route")
            .replace("/usr/sbin/arp", "mock_arp")
        )
        harness = f"""
LOOPBACK_OUTPUT="$1"
GATEWAY="$2"
ROUTE_INTERFACE="$3"
ARP_OUTPUT="$4"
FAIL_COMMAND="$5"
mock_ifconfig() {{
    [ "$FAIL_COMMAND" != "ifconfig" ] || return 1
    printf '%s' "$LOOPBACK_OUTPUT"
}}
mock_route() {{
    [ "$FAIL_COMMAND" != "route" ] || return 1
    printf 'gateway: %s\\ninterface: %s\\n' "$GATEWAY" "$ROUTE_INTERFACE"
}}
mock_arp() {{
    [ "$FAIL_COMMAND" != "arp" ] || return 1
    printf '%s' "$ARP_OUTPUT"
}}
{functions}
legacy_network_state_is_safe
"""

        def check(
            loopback: str = safe_loopback,
            gateway: str = "192.168.1.1",
            route_interface: str = "en0",
            arp_output: str = "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0\n",
            fail_command: str = "none",
            shell_harness: str = harness,
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    shell_harness,
                    "legacy-network-check",
                    loopback,
                    gateway,
                    route_interface,
                    arp_output,
                    fail_command,
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        assert check().returncode == 0
        assert check(loopback="lo0: flags=8049<UP,LOOPBACK>\n").returncode != 0
        assert (
            check(
                loopback=safe_loopback
                + "    inet 192.168.1.200 netmask 0xffffffff\n"
            ).returncode
            != 0
        )
        assert (
            check(
                loopback=safe_loopback
                + "    inet 203.0.113.1 netmask 0xffffffff\n",
                gateway="203.0.113.1",
            ).returncode
            != 0
        )
        assert (
            check(
                arp_output=(
                    "? (192.168.1.200) at aa:bb:cc:dd:ee:ff "
                    "on en0 ifscope permanent published (proxy only)\n"
                )
            ).returncode
            != 0
        )
        assert check(fail_command="route").returncode == 0
        for command in ("ifconfig", "arp"):
            assert check(fail_command=command).returncode != 0

        legacy_guard = script.index(
            'if [ "$state_was_loaded" -eq 0 ]; then'
        )
        pf_check = script.index(
            "if ! squirrelops_pf_anchor_is_empty; then",
            legacy_guard,
        )
        network_check = script.index(
            "if ! legacy_network_state_is_safe; then",
            pf_check,
        )
        flush = script.index(
            "/sbin/pfctl -a com.apple/squirrelops -F all",
            network_check,
        )
        assert legacy_guard < pf_check < network_check < flush
        assert "manual cleanup is required" in script[network_check:flush]


def test_empty_root_helper_marker_authorizes_block_only_anchor_flush() -> None:
    for relative_path in (
        "scripts/pkg/app-scripts/preinstall",
        "scripts/pkg/uninstall.sh",
    ):
        script = (REPO_ROOT / relative_path).read_text()
        initialize = script.index("helper_state_is_authoritative=0")
        validate_directory = script.index(
            "Helper alias ownership directory has unsafe permissions",
            initialize,
        )
        mark_authoritative = script.index(
            "helper_state_is_authoritative=1",
            validate_directory,
        )
        optional_ledger = script.index(
            'if [ -e "$HELPER_ALIAS_STATE" ]',
            mark_authoritative,
        )
        trust_marker = script.index(
            'if [ "$helper_state_is_authoritative" -eq 1 ]; then',
            optional_ledger,
        )
        authorize_empty = script.index(
            "state_was_loaded=1",
            trust_marker,
        )
        legacy_guard = script.index(
            'if [ "$state_was_loaded" -eq 0 ]; then',
            authorize_empty,
        )
        flush = script.index(
            "/sbin/pfctl -a com.apple/squirrelops -F all",
            legacy_guard,
        )

        assert (
            initialize
            < validate_directory
            < mark_authoritative
            < optional_ledger
            < trust_marker
            < authorize_empty
            < legacy_guard
            < flush
        )
        assert "crash after" in script[trust_marker:authorize_empty]
        assert "block-only PF quarantine" in script[trust_marker:authorize_empty]


def test_initialized_helper_state_never_interprets_sensor_database() -> None:
    for relative_path in (
        "scripts/pkg/app-scripts/preinstall",
        "scripts/pkg/uninstall.sh",
    ):
        script = (REPO_ROOT / relative_path).read_text()

        assert 'HELPER_STATE_DIR="/var/db/com.squirrelops.helper"' in script
        assert 'HELPER_ALIAS_STATE="/var/db/com.squirrelops.helper/owned-aliases"' in script
        assert "never interpret the sensor-writable database" in script
        assert "/usr/bin/sqlite3" not in script
        assert "SELECT " not in script
        assert "UPDATE " not in script


def test_uninstaller_always_removes_secret_bearing_upgrade_snapshots() -> None:
    script = (REPO_ROOT / "scripts/pkg/uninstall.sh").read_text()

    assert 'BACKUP_ROOT="/Library/SquirrelOps/backups"' in script
    remove_backups = script.index('rm -rf -- "$BACKUP_ROOT"')
    remove_data = script.index('if [[ "$REMOVE_DATA" =~ ^[Yy]$ ]]; then')
    assert remove_backups < remove_data
    assert "Upgrade snapshots were preserved" not in script
    assert "local pairing credentials" in script


def test_uninstaller_noninteractive_data_modes_execute_in_bash() -> None:
    script = (REPO_ROOT / "scripts/pkg/uninstall.sh").read_text()
    harness = "\n".join(
        (
            _shell_function(script, "parse_uninstall_options"),
            _shell_function(script, "select_remove_data"),
            'YELLOW=""',
            'NC=""',
            'parse_uninstall_options "$@" || exit $?',
            'select_remove_data "${SHELL_TEST_USER_STATE:-1}"',
            'printf "%s:%s\\n" "$REMOVE_DATA_MODE" "$REMOVE_DATA"',
        )
    )

    interactive = subprocess.run(
        ["/bin/bash", "-c", harness, "uninstall-options"],
        check=False,
        capture_output=True,
        text=True,
        env={"SHELL_TEST_USER_STATE": "0"},
    )
    preserve = subprocess.run(
        ["/bin/bash", "-c", harness, "uninstall-options", "--preserve-data"],
        check=False,
        capture_output=True,
        text=True,
    )
    preserve_empty = subprocess.run(
        ["/bin/bash", "-c", harness, "uninstall-options", "--preserve-data"],
        check=False,
        capture_output=True,
        text=True,
        env={"SHELL_TEST_USER_STATE": "0"},
    )
    remove = subprocess.run(
        ["/bin/bash", "-c", harness, "uninstall-options", "--remove-data"],
        check=False,
        capture_output=True,
        text=True,
    )
    conflicting = subprocess.run(
        [
            "/bin/bash",
            "-c",
            harness,
            "uninstall-options",
            "--preserve-data",
            "--remove-data",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    unknown = subprocess.run(
        ["/bin/bash", "-c", harness, "uninstall-options", "--surprise"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert interactive.returncode == 0
    assert interactive.stdout == "interactive:y\n"
    assert preserve.returncode == 0
    assert preserve.stdout == "preserve:n\n"
    assert preserve_empty.returncode == 0
    assert preserve_empty.stdout == "preserve:y\n"
    assert remove.returncode == 0
    assert remove.stdout == "remove:y\n"
    assert conflicting.returncode == 2
    assert "mutually exclusive" in conflicting.stderr
    assert unknown.returncode == 2
    assert "Unknown uninstall option" in unknown.stderr
    assert "read -r REMOVE_DATA < /dev/tty" in _shell_function(
        script,
        "select_remove_data",
    )


def test_uninstaller_uses_root_owned_clean_marker_instead_of_database_mutation() -> None:
    script = (REPO_ROOT / "scripts/pkg/uninstall.sh").read_text()

    retire_ledger = script.index('rm -f -- "$HELPER_ALIAS_STATE"')
    remove_helper = script.index(
        'rm -f "$HELPER_PLIST" "$HELPER_BINARY" "$HELPER_SOCKET"'
    )
    select_mode = script.index('select_remove_data "$USER_STATE_PRESENT"')
    preserve_marker = script.index(
        '/usr/bin/install -d -o root -g wheel -m 700 "$HELPER_STATE_DIR"'
    )
    remove_marker = script.index('rm -rf -- "$HELPER_STATE_DIR"')

    assert retire_ledger < remove_helper < select_mode < remove_marker < preserve_marker
    assert "/usr/bin/sqlite3" not in script
    assert "mark_authoritative_rows_released" not in script
    assert "clean-uninstall marker" in script


def test_sensor_controlled_sqlite_schema_cannot_reach_root_cleanup_path(
    tmp_path: Path,
) -> None:
    database = tmp_path / "squirrelops.db"
    sentinel = tmp_path / "privileged-write"
    malicious_schema = f"""
        CREATE TABLE virtual_ips (
            ip_address TEXT NOT NULL,
            interface TEXT NOT NULL,
            released_at TEXT
        );
        CREATE TRIGGER privileged_write
        BEFORE UPDATE ON virtual_ips
        BEGIN
            SELECT writefile('{sentinel}', X'726f6f74');
        END;
        CREATE VIEW privileged_read AS
            SELECT readfile('{sentinel}') AS payload;
    """
    subprocess.run(
        ["/usr/bin/sqlite3", str(database), malicious_schema],
        check=True,
        capture_output=True,
        text=True,
    )

    for relative_path in (
        "scripts/pkg/app-scripts/preinstall",
        "scripts/pkg/uninstall.sh",
    ):
        script_path = REPO_ROOT / relative_path
        script = script_path.read_text()
        assert "/usr/bin/sqlite3" not in script
        assert "squirrelops.db" not in script
        subprocess.run(
            ["/bin/bash", "-n", str(script_path)],
            check=True,
            capture_output=True,
            text=True,
        )

    assert not sentinel.exists()


def test_mutable_tree_validation_rejects_links_and_special_files(
    tmp_path: Path,
) -> None:
    owner = subprocess.run(
        ["/usr/bin/id", "-un"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    group = subprocess.run(
        ["/usr/bin/id", "-gn"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    safe_tree = tmp_path / "safe"
    safe_tree.mkdir()
    (safe_tree / "nested").mkdir()
    (safe_tree / "nested" / "state.db").write_bytes(b"state")

    hardlink_tree = tmp_path / "hardlink"
    hardlink_tree.mkdir()
    hardlink_source = tmp_path / "hardlink-source"
    hardlink_source.write_bytes(b"linked")
    os.link(hardlink_source, hardlink_tree / "linked-state")

    symlink_tree = tmp_path / "symlink"
    symlink_tree.mkdir()
    (symlink_tree / "linked-state").symlink_to(hardlink_source)

    fifo_tree = tmp_path / "fifo"
    fifo_tree.mkdir()
    os.mkfifo(fifo_tree / "unexpected-fifo")

    acl_tree = tmp_path / "acl"
    acl_tree.mkdir()
    acl_file = acl_tree / "state.db"
    acl_file.write_bytes(b"state")
    subprocess.run(
        ["/bin/chmod", "+a", "everyone allow read", str(acl_file)],
        check=True,
        capture_output=True,
        text=True,
    )

    for relative_path in (
        "scripts/pkg/preinstall",
        "scripts/pkg/postinstall",
    ):
        script = (REPO_ROOT / relative_path).read_text()
        harness = "\n".join(
            (
                "set -o pipefail",
                _shell_function(script, "path_has_no_extended_acl"),
                _shell_function(script, "validate_mutable_tree"),
                'SENSOR_USER="$1"',
                'SENSOR_GROUP="$2"',
                'validate_mutable_tree "$3"',
            )
        )

        def validate(
            path: Path,
            shell_harness: str = harness,
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    shell_harness,
                    "validate-tree",
                    owner,
                    group,
                    str(path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        assert validate(safe_tree).returncode == 0
        assert validate(hardlink_tree).returncode != 0
        assert validate(symlink_tree).returncode != 0
        assert validate(fifo_tree).returncode != 0
        assert validate(acl_tree).returncode != 0


def test_package_quiesces_exact_service_identity_before_storage_transition() -> None:
    preinstall = (REPO_ROOT / "scripts/pkg/preinstall").read_text()
    postinstall = (REPO_ROOT / "scripts/pkg/postinstall").read_text()

    for script in (preinstall, postinstall):
        assert '"/Users/${SENSOR_USER}" "UniqueID"' in script
        assert '"/Users/${SENSOR_USER}" "PrimaryGroupID"' in script
        assert '"/Users/${SENSOR_USER}" "UserShell"' in script
        assert '"/Users/${SENSOR_USER}" "NFSHomeDirectory"' in script
        assert '"/Users/${SENSOR_USER}" "IsHidden"' in script
        assert '"/Groups/${SENSOR_GROUP}" "PrimaryGroupID"' in script
        assert '[ "$SENSOR_UID" -ge 300 ]' in script
        assert '[ "$SENSOR_UID" -le 499 ]' in script
        assert '[ "$SENSOR_GID" = "$SENSOR_UID" ]' in script
        assert '[ "$shell" = "/usr/bin/false" ]' in script
        assert '[ "$home" = "/var/empty" ]' in script
        assert '[ "$hidden" = "1" ]' in script
        assert "/usr/bin/dscl . -list /Users UniqueID" in script
        assert "/usr/bin/dscl . -list /Groups PrimaryGroupID" in script
        assert "/usr/bin/pgrep -u \"$SENSOR_UID\" '.*'" in script
        assert "/usr/bin/pkill -KILL -u \"$SENSOR_UID\" '.*'" in script
        assert '/usr/bin/crontab -u "$SENSOR_USER" -r' in script
        assert "! sensor_processes_are_running" in script
        assert "chown -R" not in script

    stop_sensor = preinstall.index(
        'stop_service_and_verify "$PLIST_NAME" "sensor service"'
    )
    quarantine = preinstall.index(
        "if ! prepare_existing_mutable_state; then",
        stop_sensor,
    )
    snapshot = preinstall.index("if ! create_upgrade_snapshot; then")
    assert stop_sensor < quarantine < snapshot

    quiesce = postinstall.index("if ! terminate_sensor_processes; then")
    prepare_data = postinstall.index(
        'quarantine_mutable_root "$DATA_DIR"',
        quiesce,
    )
    quiesce_again = postinstall.index(
        "if ! remove_sensor_crontab || ! terminate_sensor_processes; then",
        prepare_data,
    )
    validate = postinstall.index(
        'if ! validate_mutable_tree "$DATA_DIR"',
        quiesce_again,
    )
    transfer = postinstall.index(
        '/usr/sbin/chown "${SENSOR_USER}:${SENSOR_GROUP}"',
        validate,
    )
    helper_recheck = postinstall.index(
        "Sensor UID process reappeared before helper restart",
        transfer,
    )
    helper_restart = postinstall.index(
        'launchctl kickstart -k "system/${HELPER_LABEL}"',
        helper_recheck,
    )
    assert (
        quiesce
        < prepare_data
        < quiesce_again
        < validate
        < transfer
        < helper_recheck
        < helper_restart
    )


def test_directory_service_parser_accepts_exact_native_attribute_name() -> None:
    for relative_path in (
        "scripts/pkg/app-scripts/preinstall",
        "scripts/pkg/preinstall",
        "scripts/pkg/postinstall",
        "scripts/pkg/uninstall.sh",
    ):
        script = (REPO_ROOT / relative_path).read_text()
        parser = _shell_function(
            script,
            "directory_service_value",
        ).replace("/usr/bin/dscl", "mock_dscl")
        harness = f"""
MODE="$1"
mock_dscl() {{
    case "$MODE" in
        plain) printf '%s: 1\\n' "$4" ;;
        native) printf 'dsAttrTypeNative:%s: 1\\n' "$4" ;;
        duplicate)
            printf '%s: 1\\n' "$4"
            printf 'dsAttrTypeNative:%s: 1\\n' "$4"
            ;;
        multiword) printf '%s: SquirrelOps Sensor\\n' "$4" ;;
        wrong) printf 'dsAttrTypeNative:Other: 1\\n' ;;
        malformed) printf 'dsAttrTypeNative:%s: 1 extra\\n' "$4" ;;
    esac
}}
{parser}
directory_service_value "/Users/_squirrelops" "IsHidden"
"""

        for mode in ("plain", "native"):
            result = subprocess.run(
                ["/bin/bash", "-c", harness, "directory-service", mode],
                check=False,
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0, (
                relative_path,
                mode,
                result.stderr,
            )
            assert result.stdout == "1\n"

        for mode in ("duplicate", "wrong", "malformed"):
            result = subprocess.run(
                ["/bin/bash", "-c", harness, "directory-service", mode],
                check=False,
                capture_output=True,
                text=True,
            )
            assert result.returncode != 0, (relative_path, mode)

        native_other_key = harness.replace(
            'directory_service_value "/Users/_squirrelops" "IsHidden"',
            'directory_service_value "/Users/_squirrelops" "UniqueID"',
        )
        result = subprocess.run(
            [
                "/bin/bash",
                "-c",
                native_other_key,
                "directory-service",
                "native",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0, relative_path

        if "directory_service_text_value() {" not in script:
            continue
        text_parser = _shell_function(
            script,
            "directory_service_text_value",
        ).replace("/usr/bin/dscl", "mock_dscl")
        text_harness = harness.replace(parser, text_parser).replace(
            "directory_service_value ",
            "directory_service_text_value ",
        )
        for mode in ("plain", "native"):
            result = subprocess.run(
                ["/bin/bash", "-c", text_harness, "directory-service", mode],
                check=False,
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0, (
                relative_path,
                mode,
                result.stderr,
            )
            assert result.stdout == "1\n"
        for mode in ("duplicate", "wrong"):
            result = subprocess.run(
                ["/bin/bash", "-c", text_harness, "directory-service", mode],
                check=False,
                capture_output=True,
                text=True,
            )
            assert result.returncode != 0, (relative_path, mode)
        native_other_key = text_harness.replace(
            'directory_service_text_value "/Users/_squirrelops" "IsHidden"',
            'directory_service_text_value "/Users/_squirrelops" "RealName"',
        )
        result = subprocess.run(
            [
                "/bin/bash",
                "-c",
                native_other_key,
                "directory-service",
                "native",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0, relative_path

        multiword_real_name = text_harness.replace(
            'directory_service_text_value "/Users/_squirrelops" "IsHidden"',
            'directory_service_text_value "/Users/_squirrelops" "RealName"',
        )
        result = subprocess.run(
            [
                "/bin/bash",
                "-c",
                multiword_real_name,
                "directory-service",
                "multiword",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (relative_path, result.stderr)
        assert result.stdout == "SquirrelOps Sensor\n"


def test_cleanup_scripts_quiesce_detached_sensor_before_and_after_alias_cleanup() -> None:
    cases = (
        (
            "scripts/pkg/app-scripts/preinstall",
            'stop_service_and_verify "$SENSOR_LABEL" "sensor daemon"',
            'stop_service_and_verify "$HELPER_LABEL" "privileged helper daemon"',
            "aborting upgrade",
        ),
        (
            "scripts/pkg/uninstall.sh",
            'stop_service_and_verify "$PLIST_NAME" "sensor service"',
            'stop_service_and_verify "$HELPER_LABEL" "privileged helper"',
            "aborting uninstall",
        ),
    )
    for relative_path, stop_sensor_text, stop_helper_text, _ in cases:
        script = (REPO_ROOT / relative_path).read_text()

        for required in (
            '"/Users/${SENSOR_USER}" "UniqueID"',
            '"/Users/${SENSOR_USER}" "PrimaryGroupID"',
            '"/Users/${SENSOR_USER}" "UserShell"',
            '"/Users/${SENSOR_USER}" "NFSHomeDirectory"',
            '"/Users/${SENSOR_USER}" "IsHidden"',
            '"/Groups/${SENSOR_GROUP}" "PrimaryGroupID"',
            "/usr/bin/dscl . -list /Users UniqueID",
            "/usr/bin/dscl . -list /Groups PrimaryGroupID",
            "/usr/bin/pgrep -u \"$SENSOR_UID\" '.*'",
            "/usr/bin/pkill -KILL -u \"$SENSOR_UID\" '.*'",
            '/usr/bin/crontab -u "$SENSOR_USER" -r',
        ):
            assert required in script

        stop_sensor = script.index(stop_sensor_text)
        first_quiesce = script.index(
            "if ! quiesce_sensor_identity; then",
            stop_sensor,
        )
        stop_helper = script.index(stop_helper_text, first_quiesce)
        read_ledger = script.index(
            'helper_alias_rows=$(/bin/cat "$HELPER_ALIAS_STATE")',
            stop_helper,
        )
        second_quiesce = script.index(
            "if ! quiesce_sensor_identity; then",
            read_ledger,
        )
        verify_pf = script.index(
            "/sbin/pfctl -a com.apple/squirrelops -F all",
            second_quiesce,
        )
        verify_aliases = script.index(
            "if ! tracked_network_state_is_absent; then",
            verify_pf,
        )
        retire_ledger = script.index(
            'rm -f -- "$HELPER_ALIAS_STATE"',
            verify_aliases,
        )
        assert (
            stop_sensor
            < first_quiesce
            < stop_helper
            < read_ledger
            < second_quiesce
            < verify_pf
            < verify_aliases
            < retire_ledger
        )


def test_partial_install_without_service_account_remains_recoverable() -> None:
    app_preinstall = (
        REPO_ROOT / "scripts/pkg/app-scripts/preinstall"
    ).read_text()
    sensor_preinstall = (REPO_ROOT / "scripts/pkg/preinstall").read_text()

    app_quiesce = _shell_function(
        app_preinstall,
        "quiesce_sensor_identity",
    )
    missing_account = app_quiesce.index(
        '! /usr/bin/dscl . -read "/Users/${SENSOR_USER}"'
    )
    safe_return = app_quiesce.index("return 0", missing_account)
    validate = app_quiesce.index("validate_service_identity")
    assert missing_account < safe_return < validate
    assert "partial first install" in app_quiesce

    prepare = _shell_function(
        sensor_preinstall,
        "prepare_existing_mutable_state",
    )
    missing_account = prepare.index(
        '! /usr/bin/dscl . -read "/Users/${SENSOR_USER}"'
    )
    quarantine = prepare.index(
        'quarantine_mutable_tree "$mutable_root"',
        missing_account,
    )
    require_empty = prepare.index(
        '-xdev -mindepth 1 -print -quit',
        quarantine,
    )
    safe_return = prepare.index("return 0", require_empty)
    validate = prepare.index("validate_service_identity", safe_return)
    assert missing_account < quarantine < require_empty < safe_return < validate


def test_service_account_provisioning_commits_final_identity_atomically() -> None:
    script = (REPO_ROOT / "scripts/pkg/postinstall").read_text()

    write_marker = script.index('write_account_provisioning_id "$new_id"')
    create_group = script.index(
        '/usr/bin/dscl . -create "/Groups/${STAGED_SENSOR_GROUP}"',
        write_marker,
    )
    create_user = script.index(
        '/usr/bin/dscl . -create "/Users/${STAGED_SENSOR_USER}"',
        create_group,
    )
    rename_group = script.index(
        '"/Groups/${STAGED_SENSOR_GROUP}" RecordName',
        create_user,
    )
    rename_user = script.index(
        '"/Users/${STAGED_SENSOR_USER}" RecordName',
        rename_group,
    )
    validate = script.index("if ! validate_service_identity; then", rename_user)
    retire_marker = script.index(
        "retire_account_provisioning_marker",
        validate,
    )
    create_call = script.index("if ! create_service_account; then")
    terminate_definition = script.index("terminate_sensor_processes() {")
    create_storage = script.index("# Step 1: Create data directories")

    assert (
        write_marker
        < create_group
        < create_user
        < rename_group
        < rename_user
        < validate
        < retire_marker
    )
    assert terminate_definition < create_call < create_storage
    assert "RUN_AS_SERVICE_ACCOUNT=1" in script[create_call:create_storage]


def test_account_markers_are_durable_and_cross_workflow_recoverable() -> None:
    postinstall = (REPO_ROOT / "scripts/pkg/postinstall").read_text()
    app_preinstall = (
        REPO_ROOT / "scripts/pkg/app-scripts/preinstall"
    ).read_text()
    uninstall = (REPO_ROOT / "scripts/pkg/uninstall.sh").read_text()

    for script in (postinstall, app_preinstall, uninstall):
        assert (
            'ACCOUNT_DEPROVISIONING_MARKER='
            '"$ACCOUNT_PROVISIONING_DIR/account-deprovisioning"'
        ) in script
        assert "deprovisioning_records_match_id()" in script
        assert '"RealName" "SquirrelOps Sensor"' in script
        assert '"UserShell" "/usr/bin/false"' in script
        assert '"NFSHomeDirectory" "/var/empty"' in script
        assert '"GroupMembership"' in script
        assert '"GroupMembers"' in script
        cleanup = _shell_function(
            script,
            "cleanup_interrupted_account_deprovisioning",
        )
        retire_marker = cleanup.index(
            'rm -f -- "$ACCOUNT_DEPROVISIONING_MARKER"'
        )
        retire_directory = cleanup.index(
            "retire_account_provisioning_dir || return 1",
            retire_marker,
        )
        sync_retirement = cleanup.index("/bin/sync", retire_directory)
        assert retire_marker < retire_directory < sync_retirement

    for script in (app_preinstall, uninstall):
        marker_write = script.index(
            '"$ACCOUNT_DEPROVISIONING_MARKER" \\\n'
            "        || ! /bin/sync"
        )
        delete_user = script.index(
            '/usr/bin/dscl . -delete "/Users/${SENSOR_USER}"',
            marker_write,
        )
        assert marker_write < delete_user
        assert "recover_legacy_partial_service_identity()" in script
        assert (
            "recover_unmarked_legacy_identity_for_existing_install()"
            in script
        )

    assert "recover_legacy_partial_service_identity" not in postinstall
    assert "legacy_partial_account_id" not in postinstall
    assert "write_account_deprovisioning_id" not in postinstall

    provisioning_write = postinstall.index(
        '"$ACCOUNT_PROVISIONING_MARKER" \\\n'
        "        || ! /bin/sync"
    )
    create_group = postinstall.index(
        '/usr/bin/dscl . -create "/Groups/${STAGED_SENSOR_GROUP}"'
    )
    assert provisioning_write < create_group

    app_recovery = app_preinstall.index(
        "if ! cleanup_interrupted_account_deprovisioning"
    )
    app_quiesce = app_preinstall.index(
        "if ! quiesce_sensor_identity; then",
        app_recovery,
    )
    uninstall_recovery = uninstall.index(
        "if ! cleanup_interrupted_account_deprovisioning"
    )
    uninstall_quiesce = uninstall.index(
        "if ! quiesce_sensor_identity; then",
        uninstall_recovery,
    )
    create_account = postinstall.index("create_service_account() {")
    postinstall_recovery = postinstall.index(
        "if ! cleanup_interrupted_account_deprovisioning",
        create_account,
    )
    existing_user = postinstall.index(
        'if /usr/bin/dscl . -read "/Users/${SENSOR_USER}"',
        postinstall_recovery,
    )
    assert app_recovery < app_quiesce
    assert uninstall_recovery < uninstall_quiesce
    assert postinstall_recovery < existing_user


def test_unmarked_legacy_recovery_requires_preexisting_install_footprint() -> None:
    for relative_path in (
        "scripts/pkg/app-scripts/preinstall",
        "scripts/pkg/uninstall.sh",
    ):
        script = (REPO_ROOT / relative_path).read_text()
        gate_name = "recover_unmarked_legacy_identity_for_existing_install"
        footprint_start = script.index("EXISTING_SENSOR_INSTALL=0")
        gate_start = script.index(f"{gate_name}() {{", footprint_start)
        footprint = script[footprint_start:gate_start]
        gate = _shell_function(script, gate_name)

        # Account names and recovery markers do not count as independent proof
        # of an existing installation.
        assert "/Users/${SENSOR_USER}" not in footprint
        assert "/Groups/${SENSOR_GROUP}" not in footprint
        assert "ACCOUNT_PROVISIONING_DIR" not in footprint

        harness = f"""
EXISTING_SENSOR_INSTALL="$1"
GROUP_PRESENT=1
DELETE_ATTEMPTS=0
recover_legacy_partial_service_identity() {{
    DELETE_ATTEMPTS=$((DELETE_ATTEMPTS + 1))
    GROUP_PRESENT=0
}}
{gate}
{gate_name} || exit $?
printf 'group=%s deletes=%s\\n' "$GROUP_PRESENT" "$DELETE_ATTEMPTS"
"""
        fresh = subprocess.run(
            ["/bin/bash", "-c", harness, "legacy-recovery", "0"],
            check=False,
            capture_output=True,
            text=True,
        )
        existing = subprocess.run(
            ["/bin/bash", "-c", harness, "legacy-recovery", "1"],
            check=False,
            capture_output=True,
            text=True,
        )

        assert fresh.returncode == 0, (relative_path, fresh.stderr)
        assert fresh.stdout == "group=1 deletes=0\n"
        assert existing.returncode == 0, (relative_path, existing.stderr)
        assert existing.stdout == "group=0 deletes=1\n"


def test_account_provisioning_marker_retirement_is_durable() -> None:
    for relative_path in (
        "scripts/pkg/postinstall",
        "scripts/pkg/uninstall.sh",
    ):
        script = (REPO_ROOT / relative_path).read_text()
        retire = _shell_function(
            script,
            "retire_account_provisioning_marker",
        )
        remove_marker = retire.index(
            'rm -f -- "$ACCOUNT_PROVISIONING_MARKER"'
        )
        remove_directory = retire.index(
            "retire_account_provisioning_dir",
            remove_marker,
        )
        durable = retire.index("/bin/sync", remove_directory)

        assert remove_marker < remove_directory < durable
        assert script.count("retire_account_provisioning_marker") == 3


def test_legacy_partial_account_matcher_is_tightly_bounded() -> None:
    for relative_path in (
        "scripts/pkg/app-scripts/preinstall",
        "scripts/pkg/postinstall",
        "scripts/pkg/uninstall.sh",
    ):
        script = (REPO_ROOT / relative_path).read_text()
        matcher = _shell_function(
            script,
            "deprovisioning_records_match_id",
        ).replace("/usr/bin/dscl", "mock_dscl")
        harness = f"""
MODE="$1"
SENSOR_USER="_squirrelops"
SENSOR_GROUP="_squirrelops"
record_value_matches_or_is_missing() {{
    [ "$MODE:$2" != "bad-shell:UserShell" ]
}}
directory_service_value() {{
    if [ "$MODE" = "bad-gid" ]; then
        printf '310\\n'
    else
        printf '309\\n'
    fi
}}
record_attribute_is_empty_or_missing() {{
    [ "$MODE" != "member" ]
}}
mock_dscl() {{
    case "$2:$3" in
        -read:/Users/_squirrelops)
            [ "$MODE" != "group-only" ]
            return
            ;;
        -read:/Groups/_squirrelops) return 0 ;;
        -list:/Users)
            [ "$MODE" != "user-conflict" ] || printf 'other 309\\n'
            return 0
            ;;
        -list:/Groups)
            printf '_squirrelops 309\\n'
            [ "$MODE" != "group-conflict" ] || printf 'other 309\\n'
            return 0
            ;;
        *) return 1 ;;
    esac
}}
{matcher}
deprovisioning_records_match_id 309
"""

        def check(
            mode: str,
            shell_harness: str = harness,
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["/bin/bash", "-c", shell_harness, "legacy-account", mode],
                check=False,
                capture_output=True,
                text=True,
            )

        assert check("group-only").returncode == 0
        assert check("partial-user").returncode == 0
        for mode in (
            "bad-shell",
            "bad-gid",
            "member",
            "user-conflict",
            "group-conflict",
        ):
            assert check(mode).returncode != 0, (relative_path, mode)


def test_staged_account_recovery_accepts_marker_authorized_missing_ids() -> None:
    for relative_path in (
        "scripts/pkg/postinstall",
        "scripts/pkg/uninstall.sh",
    ):
        script = (REPO_ROOT / relative_path).read_text()
        functions = "\n".join(
            (
                _shell_function(script, "directory_service_value"),
                _shell_function(script, "record_id_matches_or_is_unset"),
            )
        ).replace("/usr/bin/dscl", "mock_dscl")
        harness = f"""
set -o pipefail
MODE="$1"
mock_dscl() {{
    if [ "$MODE" = "absent_record" ]; then
        return 1
    fi
    if [ "$#" -eq 3 ]; then
        return 0
    fi
    if [ "$MODE" = "absent_key" ]; then
        return 1
    fi
    case "$MODE" in
        matching) printf '%s: 309\\n' "$4" ;;
        wrong) printf '%s: 310\\n' "$4" ;;
        malformed)
            printf '%s: 309\\n' "$4"
            printf '%s: 309\\n' "$4"
            ;;
    esac
}}
{functions}
record_id_matches_or_is_unset "/Users/_squirrelops_installing" "$2" 309
"""
        for key in ("UniqueID", "PrimaryGroupID"):
            for mode in ("absent_record", "absent_key", "matching"):
                result = subprocess.run(
                    ["/bin/bash", "-c", harness, "account-recovery", mode, key],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                assert result.returncode == 0, (
                    relative_path,
                    key,
                    mode,
                    result.stderr,
                )
            for mode in ("wrong", "malformed"):
                result = subprocess.run(
                    ["/bin/bash", "-c", harness, "account-recovery", mode, key],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                assert result.returncode != 0, (
                    relative_path,
                    key,
                    mode,
                )


def test_uninstaller_retires_only_marker_authorized_partial_account() -> None:
    script = (REPO_ROOT / "scripts/pkg/uninstall.sh").read_text()
    cleanup = _shell_function(
        script,
        "cleanup_interrupted_account_provisioning",
    )

    for required in (
        'ACCOUNT_PROVISIONING_MARKER="$ACCOUNT_PROVISIONING_DIR/account-provisioning"',
        'STAGED_SENSOR_USER="_squirrelops_installing"',
        'STAGED_SENSOR_GROUP="_squirrelops_installing"',
        'read_account_provisioning_id',
        'record_id_matches_or_is_unset',
        'terminate_sensor_processes',
        '/usr/bin/crontab -u "$STAGED_SENSOR_USER" -r',
        '"/Users/${STAGED_SENSOR_USER}"',
        '"/Groups/${STAGED_SENSOR_GROUP}"',
        '"/Groups/${SENSOR_GROUP}"',
        'rm -f -- "$ACCOUNT_PROVISIONING_MARKER"',
        "retire_account_provisioning_dir",
    ):
        assert required in script

    assert 'provisioned_id=$(read_account_provisioning_id)' in cleanup
    delete_partial = cleanup.index('/usr/bin/dscl . -delete "$record"')
    retire_partial_marker = cleanup.index(
        "retire_account_provisioning_marker",
        delete_partial,
    )
    assert (
        cleanup.index("record_id_matches_or_is_unset")
        < cleanup.index("terminate_sensor_processes")
        < delete_partial
        < retire_partial_marker
    )
    stop_sensor = script.index(
        'stop_service_and_verify "$PLIST_NAME" "sensor service"'
    )
    quiesce = script.index("if ! quiesce_sensor_identity; then", stop_sensor)
    cleanup_call = script.index(
        "if ! cleanup_interrupted_account_provisioning; then",
        quiesce,
    )
    read_ledger = script.index(
        'helper_alias_rows=$(/bin/cat "$HELPER_ALIAS_STATE")',
        cleanup_call,
    )
    assert stop_sensor < quiesce < cleanup_call < read_ledger


def test_uninstaller_retries_marker_authorized_partial_account_removal(
    tmp_path: Path,
) -> None:
    script = (REPO_ROOT / "scripts/pkg/uninstall.sh").read_text()
    cleanup = _shell_function(
        script,
        "cleanup_interrupted_account_deprovisioning",
    )
    cleanup = cleanup.replace("/usr/bin/dscl", "mock_dscl").replace(
        "/usr/bin/crontab",
        "mock_crontab",
    )
    marker = tmp_path / "account-deprovisioning"
    marker.write_text("309\n")
    provisioning_marker = tmp_path / "account-provisioning"
    harness = f"""
ACCOUNT_DEPROVISIONING_MARKER="$1"
ACCOUNT_PROVISIONING_MARKER="$2"
SENSOR_USER="_squirrelops"
SENSOR_GROUP="_squirrelops"
STAGED_SENSOR_USER="_squirrelops_installing"
STAGED_SENSOR_GROUP="_squirrelops_installing"
SENSOR_UID=""
USER_PRESENT=0
GROUP_PRESENT=1
read_account_deprovisioning_id() {{ printf '309\\n'; }}
record_id_matches_or_is_unset() {{ return 0; }}
validate_service_identity() {{ return 1; }}
deprovisioning_records_match_id() {{ return 0; }}
terminate_sensor_processes() {{ return 0; }}
retire_account_provisioning_dir() {{ return 0; }}
mock_crontab() {{ return 0; }}
mock_dscl() {{
    case "$2:$3" in
        -read:/Users/_squirrelops_installing) return 1 ;;
        -read:/Groups/_squirrelops_installing) return 1 ;;
        -read:/Users/_squirrelops)
            [ "$USER_PRESENT" -eq 1 ]
            return
            ;;
        -read:/Groups/_squirrelops)
            [ "$GROUP_PRESENT" -eq 1 ]
            return
            ;;
        -list:/Users) return 0 ;;
        -list:/Groups)
            [ "$GROUP_PRESENT" -eq 0 ] || printf '_squirrelops 309\\n'
            return 0
            ;;
        -delete:/Users/_squirrelops)
            USER_PRESENT=0
            return 0
            ;;
        -delete:/Groups/_squirrelops)
            GROUP_PRESENT=0
            return 0
            ;;
        *) return 1 ;;
    esac
}}
{cleanup}
cleanup_interrupted_account_deprovisioning || exit $?
printf 'user=%s group=%s\\n' "$USER_PRESENT" "$GROUP_PRESENT"
"""
    result = subprocess.run(
        [
            "/bin/bash",
            "-c",
            harness,
            "account-deprovision-retry",
            str(marker),
            str(provisioning_marker),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "user=0 group=0\n"
    assert not marker.exists()

    write_marker = script.index(
        'write_account_deprovisioning_id "$SENSOR_UID"'
    )
    cleanup_call = script.index(
        "cleanup_interrupted_account_deprovisioning",
        write_marker,
    )
    delete_user = cleanup.index(
        '/usr/bin/dscl . -delete "/Users/${SENSOR_USER}"'
        .replace("/usr/bin/dscl", "mock_dscl")
    )
    delete_group = cleanup.index(
        '/usr/bin/dscl . -delete "/Groups/${SENSOR_GROUP}"'
        .replace("/usr/bin/dscl", "mock_dscl")
    )
    retire_marker = cleanup.index(
        'rm -f -- "$ACCOUNT_DEPROVISIONING_MARKER"'
    )
    assert write_marker < cleanup_call
    assert delete_user < delete_group < retire_marker


def test_uninstaller_keeps_retry_entrypoint_until_teardown_is_complete() -> None:
    script = (REPO_ROOT / "scripts/pkg/uninstall.sh").read_text()

    remove_account = script.index(
        'write_account_deprovisioning_id "$SENSOR_UID"'
    )
    retire_helper_marker = script.index(
        'rm -rf -- "$HELPER_STATE_DIR"',
        remove_account,
    )
    remove_retry_script = script.index(
        'rm -f "$INSTALL_DIR/uninstall.sh"',
        retire_helper_marker,
    )
    remove_install_dir = script.index(
        'rmdir "$INSTALL_DIR"',
        remove_retry_script,
    )
    assert (
        remove_account
        < retire_helper_marker
        < remove_retry_script
        < remove_install_dir
    )


def test_postinstall_validates_and_isolates_embedded_python_runtime(
    tmp_path: Path,
) -> None:
    script = (REPO_ROOT / "scripts/pkg/postinstall").read_text()
    owner = subprocess.run(
        ["/usr/bin/id", "-un"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    group = subprocess.run(
        ["/usr/bin/id", "-gn"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    safe = tmp_path / "safe-python"
    (safe / "bin").mkdir(parents=True)
    interpreter = safe / "bin" / "python3.14"
    interpreter.write_bytes(b"python")
    interpreter.chmod(0o755)
    (safe / "bin" / "python3").symlink_to("python3.14")

    writable = tmp_path / "writable-python"
    (writable / "bin").mkdir(parents=True)
    writable_file = writable / "bin" / "python3"
    writable_file.write_bytes(b"python")
    writable_file.chmod(0o775)

    escaped = tmp_path / "escaped-python"
    (escaped / "bin").mkdir(parents=True)
    (escaped / "bin" / "python3").symlink_to("/bin/sh")

    acl_runtime = tmp_path / "acl-python"
    (acl_runtime / "bin").mkdir(parents=True)
    acl_file = acl_runtime / "bin" / "python3"
    acl_file.write_bytes(b"python")
    acl_file.chmod(0o755)
    subprocess.run(
        ["/bin/chmod", "+a", "everyone allow read", str(acl_file)],
        check=True,
        capture_output=True,
        text=True,
    )

    functions = "\n".join(
        (
            _shell_function(script, "runtime_entry_is_safe"),
            _shell_function(script, "validate_root_owned_python_runtime"),
        )
    )
    functions = functions.replace(
        '[ "$owner" = "root" ] && [ "$group" = "wheel" ]',
        f'[ "$owner" = "{owner}" ] && [ "$group" = "{group}" ]',
    )
    harness = "\n".join(
        (
            "set -o pipefail",
            functions,
            'validate_root_owned_python_runtime "$1"',
        )
    )

    def validate(path: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/bash", "-c", harness, "runtime-tree", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )

    assert validate(safe).returncode == 0
    assert validate(writable).returncode != 0
    assert validate(escaped).returncode != 0
    assert validate(acl_runtime).returncode != 0

    validate_call = script.index(
        'validate_root_owned_python_runtime "$PYTHON_RUNTIME"'
    )
    first_python = script.index("isolated_python -c")
    assert validate_call < first_python
    isolated = _shell_function(script, "isolated_python")
    assert "/usr/bin/env -i" in isolated
    assert '"$PYTHON_PATH" -I "$@"' in isolated
    assert (
        '/usr/bin/sudo -n -u "$SENSOR_USER" /usr/bin/env -i'
        in script
    )
    assert '"$PYTHON_PATH" -I - "$HELPER_SOCKET"' in script
    assert "isolated_python -c" in script[
        script.index("sensor_health_is_ready()") :
    ]

    plist = (
        REPO_ROOT / "sensor/resources/com.squirrelops.sensor.plist"
    ).read_text()
    python_arg = plist.index("<string>__PYTHON_PATH__</string>")
    isolated_arg = plist.index("<string>-I</string>", python_arg)
    module_arg = plist.index("<string>-m</string>", isolated_arg)
    assert python_arg < isolated_arg < module_arg


def test_upgrade_snapshots_strip_and_verify_extended_acls() -> None:
    script = (REPO_ROOT / "scripts/pkg/preinstall").read_text()
    create = _shell_function(script, "create_upgrade_snapshot")

    assert '/bin/chmod -N "$BACKUP_ROOT"' in create
    assert 'path_has_no_extended_acl "$BACKUP_ROOT"' in create
    assert '/bin/chmod -RN "$backup_dir"' in create
    assert 'snapshot_tree_is_private "$backup_dir"' in create
    complete = create.index('> "$backup_dir/COMPLETE"')
    strip = create.index('/bin/chmod -RN "$backup_dir"')
    verify = create.index('snapshot_tree_is_private "$backup_dir"')
    assert complete < strip < verify


def test_sensor_postinstall_uses_bounded_full_profile_readiness_window() -> None:
    script = (REPO_ROOT / "scripts/pkg/postinstall").read_text()

    bootstrap = script.index('launchctl bootstrap system "$PLIST_DEST"')
    deadline = script.index("HEALTH_DEADLINE=")
    health_wait = script.index("if wait_for_sensor_health; then")

    assert bootstrap < deadline < health_wait
    # Nine persisted mimics took more than four minutes to restore on a real
    # upgrade. The Full profile supports up to 10, so the bounded package
    # readiness window must cover that supported recovery path.
    timeout = int(
        next(
            line.partition("=")[2]
            for line in script.splitlines()
            if line.startswith("HEALTH_TIMEOUT_SECONDS=")
        )
    )
    assert timeout == 1200
    assert (
        timeout
        >= PROFILE_SETTINGS[ResourceProfile.FULL].max_mimic_decoys * 40
    )
    assert "HEALTH_PROBE_TIMEOUT_SECONDS=3" in script
    assert "HEALTH_INTERVAL_SECONDS=2" in script
    assert '/bin/date "+%s"' in script
    assert 'while [ "$(/bin/date "+%s")" -lt "$HEALTH_DEADLINE" ]; do' in script
    assert "TIMEOUT=30" not in script


def test_sensor_postinstall_rejects_dead_daemon_during_readiness_wait() -> None:
    script = (REPO_ROOT / "scripts/pkg/postinstall").read_text()

    assert "sensor_service_is_running()" in script
    assert '/bin/launchctl print "system/${PLIST_NAME}"' in script
    assert '/usr/bin/grep -Eq "state = running"' in script
    assert '/usr/bin/grep -Eq "pid = [1-9][0-9]*"' in script
    assert "SENSOR_LIVENESS_GRACE_SECONDS=10" in script
    assert "Sensor launchd job disappeared during startup" in script
    assert "Sensor process is not running" in script


def test_sensor_postinstall_requires_exact_healthy_response() -> None:
    script = (REPO_ROOT / "scripts/pkg/postinstall").read_text()

    assert "sensor_health_is_ready()" in script
    assert "/usr/bin/curl" in script
    assert "--connect-timeout 1" in script
    assert '--max-time "$HEALTH_PROBE_TIMEOUT_SECONDS"' in script
    assert 'payload.get("status") == "ok"' in script
    assert 'if sensor_health_is_ready; then' in script
    assert "HEALTH_REQUIRED_SUCCESSES=2" in script
    assert 'SENSOR_HEALTHY=1' in script
    assert 'if [ "$SENSOR_HEALTHY" -ne 1 ]; then' in script


def test_uninstaller_removes_runtime_but_preserves_user_state_by_default() -> None:
    script = (REPO_ROOT / "scripts/pkg/uninstall.sh").read_text()

    assert 'rm -rf "$INSTALL_DIR/python" "$INSTALL_DIR/venv"' in script
    assert 'rm -f "$INSTALL_DIR/.python-mode" "$INSTALL_DIR/VERSION"' in script
    assert 'rm -rf "$INSTALL_DIR/run" "$INSTALL_DIR/signatures"' in script

    choice = script.index('if [[ "$REMOVE_DATA" =~ ^[Yy]$ ]]; then')
    remove_config = script.index('rm -f "$INSTALL_DIR/config.yaml"')
    keep_data = script.index('info "Keeping sensor data and configuration')
    assert choice < remove_config < keep_data


def test_sensor_startup_quarantines_before_restoring_mimic_aliases() -> None:
    source = (REPO_ROOT / "sensor/src/squirrelops_home_sensor/__main__.py").read_text()

    reserve = source.index("load_from_db(restore_aliases=False)")
    quarantine = source.index("prepare_persisted_network()")
    resume = source.index("mimic_orchestrator.resume_active()")

    assert reserve < quarantine < resume


def test_sensor_shutdown_removes_aliases_before_clearing_pf() -> None:
    source = (REPO_ROOT / "sensor/src/squirrelops_home_sensor/__main__.py").read_text()

    stop = source.index('"Stopping mimic orchestrator"')
    remove_aliases = source.index("removed = await runtime.ip_manager.remove_all()")
    retain_guard = source.index("if not runtime.mimic_network_state_known:")
    clear_pf = source.index('"Clearing port forwarding rules"')

    assert stop < remove_aliases < retain_guard < clear_pf
