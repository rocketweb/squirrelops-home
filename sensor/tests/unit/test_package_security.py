"""Static package regressions for signing identity and private logs."""

from __future__ import annotations

import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


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
