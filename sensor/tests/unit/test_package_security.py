"""Static package regressions for signing identity and private logs."""

from __future__ import annotations

import plistlib
import subprocess
import tomllib
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_unsandboxed_macos_targets_keep_hardened_runtime_and_library_validation() -> None:
    sign_script = (REPO_ROOT / "scripts/sign-app.sh").read_text(encoding="utf-8")
    for entitlement_path in (
        REPO_ROOT / "app/entitlements/app.entitlements",
        REPO_ROOT / "app/entitlements/helper.entitlements",
    ):
        entitlements = plistlib.loads(entitlement_path.read_bytes())
        assert entitlements["com.apple.security.app-sandbox"] is False
        assert "com.apple.security.cs.disable-library-validation" not in entitlements

    assert sign_script.count("--options runtime") >= 2


def test_sensor_sdist_allowlists_source_and_package_metadata() -> None:
    pyproject = tomllib.loads(
        (REPO_ROOT / "sensor/pyproject.toml").read_text(encoding="utf-8")
    )
    sdist = pyproject["tool"]["hatch"]["build"]["targets"]["sdist"]

    assert set(sdist["include"]) == {"src", "pyproject.toml"}


def test_helper_is_signed_with_its_launchd_identifier() -> None:
    script = (REPO_ROOT / "scripts/sign-app.sh").read_text(encoding="utf-8")

    assert 'HELPER_BUNDLE_ID="com.squirrelops.helper"' in script
    assert '--identifier "$HELPER_BUNDLE_ID"' in script
    assert 'HELPER_SIGNATURE="$(codesign -d --verbose=4' in script
    assert '"Identifier=${HELPER_BUNDLE_ID}" <<< "$HELPER_SIGNATURE"' in script


def test_app_installer_verifies_the_copied_helper_identity_before_install() -> None:
    script = (
        REPO_ROOT / "scripts/pkg/app-scripts/postinstall"
    ).read_text(encoding="utf-8")

    assert 'EXPECTED_TEAM_ID="PSQ5HK5U65"' in script
    assert 'identifier \\"${HELPER_BUNDLE_ID}\\"' in script
    assert 'certificate leaf[subject.OU] = \\"${EXPECTED_TEAM_ID}\\"' in script
    assert '/usr/bin/codesign --verify --strict' in script
    verify_temp = script.index(
        '-R "=${HELPER_REQUIREMENT}" "$HELPER_TEMP"'
    )
    install_temp = script.index('/bin/mv -fh "$HELPER_TEMP" "$HELPER_DEST"')
    verify_installed = script.index(
        '-R "=${HELPER_REQUIREMENT}" "$HELPER_DEST"'
    )
    assert verify_temp < install_temp < verify_installed
    assert 'cp "$HELPER_SRC" "$HELPER_DEST"' not in script


def test_app_installer_removes_privileged_artifacts_that_fail_post_move_validation() -> None:
    script = (
        REPO_ROOT / "scripts/pkg/app-scripts/postinstall"
    ).read_text(encoding="utf-8")

    cleanup = script[
        script.index("cleanup_staged_files() {") :
        script.index("path_has_no_extended_acl() {")
    ]
    assert 'if [ "$HELPER_DEST_PENDING_VALIDATION" = "1" ]; then' in cleanup
    assert '/bin/rm -f -- "$HELPER_DEST"' in cleanup
    assert 'if [ "$PLIST_DEST_PENDING_VALIDATION" = "1" ]; then' in cleanup
    assert '/bin/rm -f -- "$PLIST_DEST"' in cleanup

    helper_move = script.index('/bin/mv -fh "$HELPER_TEMP" "$HELPER_DEST"')
    helper_armed = script.index('HELPER_DEST_PENDING_VALIDATION=1')
    helper_verified = script.index(
        'HELPER_DEST_PENDING_VALIDATION=0',
        helper_armed,
    )
    assert helper_move < helper_armed < helper_verified

    plist_move = script.index('/bin/mv -fh "$PLIST_TEMP" "$PLIST_DEST"')
    plist_armed = script.index('PLIST_DEST_PENDING_VALIDATION=1')
    plist_verified = script.index(
        'PLIST_DEST_PENDING_VALIDATION=0',
        plist_armed,
    )
    assert plist_move < plist_armed < plist_verified


def test_local_test_package_is_explicit_and_cannot_weaken_release_signing() -> None:
    builder = (REPO_ROOT / "scripts/build-pkg.sh").read_text(encoding="utf-8")
    signer = (REPO_ROOT / "scripts/sign-app.sh").read_text(encoding="utf-8")
    postinstall = (
        REPO_ROOT / "scripts/pkg/app-scripts/postinstall"
    ).read_text(encoding="utf-8")
    preinstall = (
        REPO_ROOT / "scripts/pkg/app-scripts/preinstall"
    ).read_text(encoding="utf-8")

    assert 'LOCAL_TEST_BUILD="${SQUIRRELOPS_LOCAL_TEST_BUILD:-0}"' in builder
    assert 'error "A release build cannot be a local test build."' in builder
    assert "com.squirrelops.local-test-build" in builder
    assert 'LOCAL_TEST_CREDENTIAL_NAMESPACE="$(/usr/bin/uuidgen)"' in builder
    assert 'SIGNING_IDENTITY="-"' in builder
    assert "Ad-hoc signing is restricted to explicit local test builds" in signer
    assert '/usr/bin/codesign --verify --deep --strict' in postinstall
    assert "Local test build must use an ad-hoc app signature" in postinstall
    assert "verify_local_test_helper" in postinstall
    assert 'LOCAL_TEST_OPT_IN="/var/db/com.squirrelops.allow-local-test"' in preinstall
    assert "root:wheel:600:1" in preinstall
    assert "one-time root-owned operator opt-in" in preinstall
    assert preinstall.count('/bin/rm -f -- "$LOCAL_TEST_OPT_IN"') == 1
    assert '/bin/rm -f -- "$LOCAL_TEST_OPT_IN"' not in postinstall

    assert (
        'error "A local test build cannot use a real signing identity: '
        '$SIGNING_IDENTITY"'
        in builder
    )
    assert '[ -z "${SIGNING_IDENTITY+x}" ]' not in builder

    native_signing = builder[
        builder.index('SIGN_NATIVE_ARGS=(codesign --force --sign "$SIGNING_IDENTITY")'):
        builder.index('SIGN_NATIVE_ARGS+=("$macho")')
    ]
    assert 'if [ "$SIGNING_IDENTITY" != "-" ]; then' in native_signing
    assert "SIGN_NATIVE_ARGS+=(--options runtime --timestamp)" in native_signing


def test_local_test_opt_in_is_checked_before_upgrade_side_effects() -> None:
    builder = (REPO_ROOT / "scripts/build-pkg.sh").read_text(encoding="utf-8")
    distribution = (
        REPO_ROOT / "scripts/pkg/distribution.xml"
    ).read_text(encoding="utf-8")
    preinstall = (
        REPO_ROOT / "scripts/pkg/app-scripts/preinstall"
    ).read_text(encoding="utf-8")
    postinstall = (
        REPO_ROOT / "scripts/pkg/app-scripts/postinstall"
    ).read_text(encoding="utf-8")

    assert "__LOCAL_TEST_BUILD__" in distribution
    assert "system.files.fileExistsAtPath" in distribution
    assert "Local test approval required" in distribution
    assert "s|__LOCAL_TEST_BUILD__|${LOCAL_TEST_BUILD}|g" in builder
    assert "APP_PACKAGE_SCRIPTS" in builder
    assert "com.squirrelops.local-test-build" in preinstall

    consume_opt_in = preinstall.index('/bin/rm -f -- "$LOCAL_TEST_OPT_IN"')
    stop_sensor = preinstall.index(
        'stop_service_and_verify "$SENSOR_LABEL" "sensor daemon"'
    )
    assert consume_opt_in < stop_sensor
    assert '/bin/rm -f -- "$LOCAL_TEST_OPT_IN"' not in postinstall


def test_app_installer_initializes_the_root_owned_alias_state_marker() -> None:
    script = (
        REPO_ROOT / "scripts/pkg/app-scripts/postinstall"
    ).read_text(encoding="utf-8")

    assert 'HELPER_STATE_DIR="/var/db/com.squirrelops.helper"' in script
    reject_unsafe = script.index(
        "Helper alias ownership directory has an unsafe file type"
    )
    initialize = script.index(
        '/usr/bin/install -d -o root -g wheel -m 700 "$HELPER_STATE_DIR"'
    )
    verify_permissions = script.index(
        'stat -f \'%Su:%Sg:%Lp\' "$HELPER_STATE_DIR"'
    )
    bootstrap = script.index('launchctl bootstrap system "$PLIST_DEST"')
    assert reject_unsafe < initialize < verify_permissions < bootstrap


def test_app_installer_strips_and_verifies_privileged_artifact_acls() -> None:
    script = (
        REPO_ROOT / "scripts/pkg/app-scripts/postinstall"
    ).read_text(encoding="utf-8")

    assert "path_has_no_extended_acl() {" in script

    helper_parent_strip = script.index(
        "/bin/chmod -N /Library/PrivilegedHelperTools"
    )
    helper_parent_verify = script.index(
        "path_has_no_extended_acl /Library/PrivilegedHelperTools"
    )
    helper_stage_strip = script.index('/bin/chmod -N "$HELPER_TEMP"')
    helper_stage_verify = script.index(
        'path_has_no_extended_acl "$HELPER_TEMP"'
    )
    helper_stage_signature = script.index(
        '-R "=${HELPER_REQUIREMENT}" "$HELPER_TEMP"'
    )
    helper_install = script.index(
        '/bin/mv -fh "$HELPER_TEMP" "$HELPER_DEST"'
    )
    helper_dest_strip = script.index('/bin/chmod -N "$HELPER_DEST"')
    helper_dest_verify = script.index(
        'path_has_no_extended_acl "$HELPER_DEST"'
    )
    helper_dest_signature = script.index(
        '-R "=${HELPER_REQUIREMENT}" "$HELPER_DEST"'
    )
    state_strip = script.index('/bin/chmod -N "$HELPER_STATE_DIR"')
    state_verify = script.index(
        'path_has_no_extended_acl "$HELPER_STATE_DIR"'
    )

    launchd_parent_strip = script.index(
        "/bin/chmod -N /Library/LaunchDaemons"
    )
    launchd_parent_verify = script.index(
        "path_has_no_extended_acl /Library/LaunchDaemons"
    )
    plist_stage_strip = script.index('/bin/chmod -N "$PLIST_TEMP"')
    plist_stage_verify = script.index(
        'path_has_no_extended_acl "$PLIST_TEMP"'
    )
    plist_lint = script.index('/usr/bin/plutil -lint "$PLIST_TEMP"')
    plist_install = script.index('/bin/mv -fh "$PLIST_TEMP" "$PLIST_DEST"')
    plist_dest_strip = script.index('/bin/chmod -N "$PLIST_DEST"')
    plist_dest_verify = script.index(
        'path_has_no_extended_acl "$PLIST_DEST"'
    )
    bootstrap = script.index('launchctl bootstrap system "$PLIST_DEST"')

    assert (
        helper_parent_strip
        < helper_parent_verify
        < helper_stage_strip
        < helper_stage_verify
        < helper_stage_signature
        < helper_install
        < helper_dest_strip
        < helper_dest_verify
        < helper_dest_signature
        < state_strip
        < state_verify
        < launchd_parent_strip
        < launchd_parent_verify
        < plist_stage_strip
        < plist_stage_verify
        < plist_lint
        < plist_install
        < plist_dest_strip
        < plist_dest_verify
        < bootstrap
    )


def test_helper_authorized_client_requirement_pins_the_release_team() -> None:
    helper_info = (
        REPO_ROOT
        / "app/Sources/SquirrelOpsHelper/Resources/helper-info.plist"
    ).read_text(encoding="utf-8")

    assert 'identifier "com.squirrelops.home"' in helper_info
    assert "anchor apple generic" in helper_info
    assert 'certificate leaf[subject.OU] = "PSQ5HK5U65"' in helper_info


def test_helper_exposes_a_signed_app_only_enrollment_mach_service() -> None:
    launchd_path = (
        REPO_ROOT
        / "app/Sources/SquirrelOpsHelper/Resources/launchd.plist"
    )
    launchd = plistlib.loads(launchd_path.read_bytes())
    enrollment_source = (
        REPO_ROOT
        / "app/Sources/SquirrelOpsHelper/LocalEnrollmentXPCService.swift"
    ).read_text(encoding="utf-8")
    protocol_source = (
        REPO_ROOT
        / "app/Sources/SquirrelOpsLocalEnrollment/LocalEnrollmentProtocol.swift"
    ).read_text(encoding="utf-8")
    installer = (
        REPO_ROOT / "scripts/pkg/app-scripts/postinstall"
    ).read_text(encoding="utf-8")

    assert launchd["MachServices"] == {
        "com.squirrelops.helper.enrollment": True,
    }
    assert "setConnectionCodeSigningRequirement" in enrollment_source
    assert 'identifier \\"com.squirrelops.home\\"' in protocol_source
    assert "anchor apple generic" in protocol_source
    assert 'certificate leaf[subject.OU] = \\"PSQ5HK5U65\\"' in protocol_source
    assert "<key>MachServices</key>" in installer
    assert "<key>com.squirrelops.helper.enrollment</key>" in installer


def test_package_enables_local_enrollment_without_overriding_an_opt_out() -> None:
    installer = (REPO_ROOT / "scripts/pkg/postinstall").read_text(encoding="utf-8")

    assert "local_enrollment_enabled: true" in installer
    assert "local_enrollment_setting_present()" in installer
    assert 'pairing.get("local_enrollment_enabled")' in installer
    assert "if ! local_enrollment_setting_present" in installer
    assert "configuration is not a mapping" in installer
    assert "Migrated local enrollment configuration is invalid" in installer


def test_package_local_enrollment_migration_handles_existing_and_missing_sections() -> None:
    installer = (REPO_ROOT / "scripts/pkg/postinstall").read_text(encoding="utf-8")
    marker = "if ! /usr/bin/awk '\n"
    program_start = installer.index(marker) + len(marker)
    program_end = installer.index("\n    ' \"$CONFIG_FILE\"", program_start)
    awk_program = installer[program_start:program_end]

    configurations = (
        (
            "profile: standard\n"
            "pairing:\n"
            "  socket_path: /private/run/pairing.sock\n"
            "alerts:\n"
            "  retention_days: 90\n"
        ),
        "profile: standard\npairing:\n  socket_path: null\n",
        "profile: standard\nalerts:\n  retention_days: 90\n",
        "profile: standard\npairing: {socket_path: /private/run/pairing.sock}\n",
    )

    for original in configurations:
        migrated = subprocess.run(
            ["/usr/bin/awk", awk_program],
            input=original,
            text=True,
            capture_output=True,
            check=True,
        ).stdout
        parsed = yaml.safe_load(migrated)
        expected = yaml.safe_load(original)
        expected.setdefault("pairing", {})["local_enrollment_enabled"] = True

        assert parsed["pairing"]["local_enrollment_enabled"] is True
        assert parsed == expected
        assert migrated.count("local_enrollment_enabled: true") == 1


def test_live_qa_timeout_is_compatible_with_stock_macos() -> None:
    script = (REPO_ROOT / "qa/live/check.sh").read_text(encoding="utf-8")

    assert "run_bounded()" in script
    assert "run_bounded 6 dns-sd" in script
    assert "run_bounded 4 dns-sd" in script
    assert "$(timeout " not in script


def test_helper_alias_mutations_are_policy_and_ownership_gated() -> None:
    source = (
        REPO_ROOT / "app/Sources/SquirrelOpsHelper/RPCMethods.swift"
    ).read_text(encoding="utf-8")
    virtual_ip_source = (
        REPO_ROOT / "app/Sources/SquirrelOpsHelper/VirtualIPSecurity.swift"
    ).read_text(encoding="utf-8")

    add_handler = source[
        source.index('router.handlers["addIPAlias"]'):
        source.index('router.handlers["setupPortForwards"]')
    ]
    remove_handler = source[
        source.index('router.handlers["removeIPAlias"]'):
        source.index("/// Validates that a string")
    ]

    assert (
        add_handler.index("validateVirtualIPAddress(")
        < add_handler.index("requireUnusedVirtualIPAddress(")
        < add_handler.index("requirePFProtectedVirtualIP(")
        < add_handler.index("requireUnchangedPFNetworkContext(")
        < add_handler.index("requirePacketFilteringEnabled(")
        < add_handler.index("virtualIPOwnership.insert(")
        < add_handler.index("publishVirtualIP(")
    )
    assert "observeIPv4DefaultRoute" in add_handler
    assert '"-n", "get", "-inet", "default"' in virtual_ip_source
    assert '"-ifscope"' not in add_handler
    assert (
        remove_handler.index("virtualIPOwnership.contains(")
        < remove_handler.index("withdrawVirtualIP(")
        < remove_handler.index("virtualIPOwnership.remove(")
    )
    assert "validateVirtualIPAddress(" not in remove_handler
    assert "interfaceIPv4Networks(" not in remove_handler
    assert 'executable: "/sbin/route"' not in remove_handler


def test_helper_arp_scan_is_observed_and_scoped_before_execution() -> None:
    rpc_source = (
        REPO_ROOT / "app/Sources/SquirrelOpsHelper/RPCMethods.swift"
    ).read_text(encoding="utf-8")
    scanner_source = (
        REPO_ROOT / "app/Sources/SquirrelOpsHelper/ARPScanner.swift"
    ).read_text(encoding="utf-8")

    scan_handler = rpc_source[
        rpc_source.index('router.handlers["runARPScan"]'):
        rpc_source.index('router.handlers["addIPAlias"]')
    ]
    route = scan_handler.index("observeIPv4DefaultRoute")
    interface = scan_handler.index('executable: "/sbin/ifconfig"')
    validate = scan_handler.index("validateARPScanCIDR(")
    scan = scan_handler.index("ARPScanner.scan(")
    assert route < interface < validate < scan
    assert "interface: route.interface" in scan_handler
    assert "let arpProcess = Process()" not in scanner_source
    assert "readARPTable(interface: interface)" in scanner_source


def test_helper_pf_mutations_require_owned_vips_and_sensor_listeners() -> None:
    source = (
        REPO_ROOT / "app/Sources/SquirrelOpsHelper/RPCMethods.swift"
    ).read_text(encoding="utf-8")
    setup = source[
        source.index('router.handlers["setupPortForwards"]'):
        source.index('router.handlers["clearPortForwards"]')
    ]
    clear = source[
        source.index('router.handlers["clearPortForwards"]'):
        source.index('router.handlers["removeIPAlias"]')
    ]

    route = setup.index("observeIPv4DefaultRoute")
    initial_address_check = setup.index(
        "guard let initialInterfaceAddresses = ipv4InterfaceAddresses()"
    )
    validate = setup.index("validatePortForwardRequest(")
    build = setup.index("buildPFRules(")
    revalidate = setup.index("revalidatePortForwardOwnership(")
    listener = setup.index("requireSensorOwnedListener(")
    network_recheck = setup.index("requireUnchangedPFNetworkContext(")
    final_address_check = setup.index(
        "guard let currentInterfaceAddresses = ipv4InterfaceAddresses()"
    )
    quarantine_recheck = setup.index(
        "requireNoLocalAddressConflictsForPreAliasQuarantine("
    )
    load = setup.index(
        'arguments: ["-a", "com.apple/squirrelops", "-f", "-"]'
    )
    assert (
        route
        < initial_address_check
        < validate
        < build
        < revalidate
        < listener
        < network_recheck
        < final_address_check
        < quarantine_recheck
        < load
    )
    assert "directPorts.isEmpty" in source
    assert "fromIP == toIP" in source
    assert "ownedIPs.isSubset(of: endpointIPs)" in source
    assert '"/usr/sbin/lsof"' in source
    assert '"-sTCP:LISTEN"' in source
    assert "$0.uid == serviceUID && $0.endpoint == expectedEndpoint" in source
    assert "quarantinePortForwardingAfterListenerRace(" in setup
    assert "requireNoLocalIPv4AddressConflicts(" in source
    assert "cleanupPFStates(for: cleanupIPs" in source
    assert 'phase: "after listener-race quarantine"' in source

    ownership_check = clear.index(
        "virtualIPOwnership.allEntries().isEmpty"
    )
    flush = clear.index(
        'arguments: ["-a", "com.apple/squirrelops", "-F", "all"]'
    )
    assert ownership_check < flush
    assert "Cannot clear PF while helper-owned aliases exist" in clear


def test_package_hardens_existing_and_new_sensor_logs() -> None:
    postinstall = (REPO_ROOT / "scripts/pkg/postinstall").read_text(
        encoding="utf-8"
    )
    preinstall = (REPO_ROOT / "scripts/pkg/preinstall").read_text(
        encoding="utf-8"
    )

    assert 'chmod 700 "$LOG_DIR"' in postinstall
    assert (
        '/usr/bin/find "$LOG_DIR" -xdev -maxdepth 1 -type f \\\n'
        '        -exec /bin/chmod 600 {} \\;'
        in postinstall
    )
    assert "chown -R" not in postinstall
    assert '-name "squirrelops-sensor.log"' in preinstall
    assert "-delete" in preinstall


def test_embedded_sensor_runtime_uses_hash_locked_dependencies() -> None:
    environment_builder = (
        REPO_ROOT / "scripts/build-sensor-venv.sh"
    ).read_text(encoding="utf-8")
    package_builder = (REPO_ROOT / "scripts/build-pkg.sh").read_text(
        encoding="utf-8"
    )
    release_workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(
        encoding="utf-8"
    )

    assert 'uv export \\\n    --project "$SENSOR_DIR" \\' in environment_builder
    assert "--locked" in environment_builder
    assert "--no-dev" in environment_builder
    assert "--no-emit-project" in environment_builder
    assert "--no-header" in environment_builder
    assert "--no-annotate" in environment_builder
    assert "--require-hashes" in environment_builder
    assert 'REQUIRED_UV_VERSION="0.10.2"' in environment_builder
    assert 'version: "0.10.2"' in release_workflow
    assert "--only-group build" in environment_builder
    assert '--build-constraints "$LOCKED_BUILD_REQUIREMENTS"' in environment_builder
    assert '--python "$ENV_PYTHON"' in environment_builder
    assert '"$ENV_PYTHON" -m pip install \\\n    --no-index \\' in environment_builder
    assert '--no-deps \\\n    "$SENSOR_WHEEL"' in environment_builder
    assert '"$ENV_PYTHON" -m pip check' in environment_builder
    assert "Locked runtime mismatch" in environment_builder
    assert (
        'cp "$SENSOR_REQUIREMENTS_LOCK" "$SENSOR_INSTALL/requirements.lock"'
        in package_builder
    )
    assert (
        'cp "$SENSOR_BUILD_REQUIREMENTS_LOCK" \\\n'
        '    "$SENSOR_INSTALL/build-requirements.lock"'
        in package_builder
    )


def test_local_test_guidance_matches_when_the_opt_in_is_consumed() -> None:
    """Operator guidance must not contradict the postinstall ordering.

    The opt-in is spent the moment the installer accepts it, so a failed
    install still requires a fresh one. Telling an operator it is consumed
    after a successful install sends them to retry with a token that is
    already gone, and describes the security control backwards.
    """
    builder = (REPO_ROOT / "scripts/build-pkg.sh").read_text(encoding="utf-8")
    assert "after a successful helper installation" not in builder
    assert "consumes the opt-in as soon as it accepts it" in builder
