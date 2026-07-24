"""Regression tests for macOS virtual-network install and removal ordering."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_app_upgrade_stops_sensor_before_privileged_helper() -> None:
    script = (REPO_ROOT / "scripts/pkg/app-scripts/preinstall").read_text()

    verify_service = script.index('launchctl print "system/${label}"')
    bootout_service = script.index('launchctl bootout "system/${label}"')
    stop_sensor = script.index(
        'stop_service_and_verify "$SENSOR_LABEL" "sensor daemon"'
    )
    state_required = script.index(
        "Cannot verify virtual-IP state for an existing installation"
    )
    validate_database = script.index('"PRAGMA quick_check;"')
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
    remove_app = script.index('rm -rf "$APP_PATH"')

    assert (
        verify_service
        < bootout_service
        < stop_sensor
        < state_required
        < validate_database
        < invalid_row
        < reject_physical
        < verify_alias
        < verify_proxy_absent
        < remove_alias
        < require_proxy_absent
        < abort_on_alias
        < clear_pf
        < stop_helper
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
    missing_state = script.index(
        "Cannot verify virtual-IP state for an existing installation"
    )
    validate_database = script.index('"PRAGMA quick_check;"')
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
    assert (
        stop_sensor
        < missing_state
        < validate_database
        < invalid_state
        < reject_physical
        < flush_pf
        < stop_helper
        < remove_helper
    )
    assert 'launchctl bootout system "$PLIST_PATH" 2>/dev/null || true' not in script
    assert 'launchctl bootout system "$HELPER_PLIST" 2>/dev/null || true' not in script
    assert '/sbin/pfctl -a com.apple/squirrelops -F all >/dev/null 2>&1 || true' not in script
    assert '/sbin/ifconfig "$virtual_interface" inet "$virtual_ip" -alias' not in script
    assert "primary_ipv4_address()" not in script
    assert "dscl . -delete /Users/_squirrelops" in script
    assert "dscl . -delete /Groups/_squirrelops" in script


def test_uninstaller_validates_database_derived_network_arguments() -> None:
    script = (REPO_ROOT / "scripts/pkg/uninstall.sh").read_text()

    query = "SELECT DISTINCT ip_address, interface FROM virtual_ips WHERE released_at IS NULL;"
    assert query in script
    assert 'is_valid_ipv4 "$virtual_ip"' in script
    assert '"$((10#$octet))" -le 255' in script
    assert '[[ ! "$virtual_interface" =~ ^[[:alnum:]]+$ ]]' in script
    assert "Invalid virtual-IP state row" in script
    assert "remaining_aliases=1" in script


def test_package_cleanup_targets_only_unreleased_host_aliases() -> None:
    query = "SELECT DISTINCT ip_address, interface FROM virtual_ips WHERE released_at IS NULL;"
    for relative_path in (
        "scripts/pkg/app-scripts/preinstall",
        "scripts/pkg/uninstall.sh",
    ):
        script = (REPO_ROOT / relative_path).read_text()
        assert query in script
        assert '"PRAGMA quick_check;"' in script
        assert 'has_loopback_host_alias "$virtual_ip"' in script
        assert 'tolower($4) == "0xffffffff"' in script
        assert 'physical_interface_for_ipv4 "$virtual_ip"' in script
        assert "Tracked virtual IP is assigned to physical interface" in script
        assert "Manual cleanup is required before continuing" in script
        assert 'if ! proxy_arp_is_absent "$virtual_interface" "$virtual_ip"; then' in script
        assert "Proxy ARP exists without a matching lo0 /32 alias" in script
        assert '/sbin/ifconfig "$virtual_interface" inet "$virtual_ip" -alias' not in script


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
    assert '/usr/bin/sqlite3 "$SENSOR_DB" "PRAGMA quick_check;"' in script
    assert '".backup \'$backup_dir/data/squirrelops.db\'"' in script
    assert (
        '/usr/bin/sqlite3 "$backup_dir/data/squirrelops.db" \\\n'
        '                "PRAGMA quick_check;"'
        in script
    )
    assert 'cp -p "$CONFIG_FILE" "$backup_dir/config.yaml"' in script
    assert 'chmod -R go-rwx "$backup_dir"' in script
    assert '"$backup_dir/COMPLETE"' in script


def test_sensor_postinstall_uses_bounded_full_profile_readiness_window() -> None:
    script = (REPO_ROOT / "scripts/pkg/postinstall").read_text()

    bootstrap = script.index('launchctl bootstrap system "$PLIST_DEST"')
    deadline = script.index("HEALTH_DEADLINE=")
    health_wait = script.index("if wait_for_sensor_health; then")

    assert bootstrap < deadline < health_wait
    assert "HEALTH_TIMEOUT_SECONDS=180" in script
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
