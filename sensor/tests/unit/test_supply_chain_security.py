"""Regression tests for release and installer supply-chain controls."""

from __future__ import annotations

import os
import re
import subprocess
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_packaged_python_runtime_is_sanitized_and_relocated(tmp_path: Path) -> None:
    build_root = tmp_path / "checkout"
    python_dir = build_root / "build/pkg/sensor-build/python"
    bin_dir = python_dir / "bin"
    cache_dir = python_dir / "lib/python3.12/site-packages/demo/__pycache__"
    metadata_dir = (
        python_dir / "lib/python3.12/site-packages/squirrelops_home_sensor-1.1.5.dist-info"
    )
    bin_dir.mkdir(parents=True)
    cache_dir.mkdir(parents=True)
    metadata_dir.mkdir(parents=True)
    python_binary = bin_dir / "python3"
    python_binary.write_bytes(b"\xcf\xfa\xed\xfe")
    python_binary.chmod(0o755)

    console_script = bin_dir / "uvicorn"
    console_script.write_text(
        f"#!{python_dir}/bin/python3\nprint('uvicorn')\n",
        encoding="utf-8",
    )
    console_script.chmod(0o755)
    (cache_dir / "demo.pyc").write_bytes(f"compiled from {build_root}/sensor/demo.py".encode())
    (metadata_dir / "direct_url.json").write_text(
        f'{{"url":"file://{build_root}/sensor"}}',
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "scripts/sanitize-python-runtime.sh"),
            "sanitize",
            str(python_dir),
            str(build_root),
            str(python_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert console_script.read_text(encoding="utf-8") == (
        "#!/Library/SquirrelOps/sensor/python/bin/python3\nprint('uvicorn')\n"
    )
    assert console_script.stat().st_mode & 0o111
    assert not list(python_dir.rglob("__pycache__"))
    assert not list(python_dir.rglob("*.pyc"))
    assert not list(python_dir.rglob("direct_url.json"))


def test_payload_validator_rejects_a_remaining_build_host_path(
    tmp_path: Path,
) -> None:
    build_root = tmp_path / "checkout"
    payload_dir = tmp_path / "staged-sensor"
    payload_dir.mkdir()
    (payload_dir / "leaked.txt").write_text(
        f"source={build_root}/sensor",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "scripts/sanitize-python-runtime.sh"),
            "validate",
            str(payload_dir),
            str(build_root),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "Build-host path remains in payload file" in result.stderr


def test_runtime_sanitizer_rejects_a_non_runtime_deletion_target(
    tmp_path: Path,
) -> None:
    unsafe_target = tmp_path / "workspace"
    cache_dir = unsafe_target / "lib/demo/__pycache__"
    (unsafe_target / "bin").mkdir(parents=True)
    cache_dir.mkdir(parents=True)

    result = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "scripts/sanitize-python-runtime.sh"),
            "sanitize",
            str(unsafe_target),
            str(tmp_path / "checkout"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert cache_dir.is_dir()
    assert "Python runtime target is unsafe" in result.stderr


def test_standalone_python_is_verified_before_extraction() -> None:
    script = (REPO_ROOT / "scripts/build-sensor-venv.sh").read_text()
    tarball_assignment = script.index('TARBALL="$OUTPUT_DIR/${PBS_FILENAME}"')
    verification = script.index('info "Verifying standalone Python SHA-256..."')
    extraction = script.index('tar -xzf "$TARBALL"')

    assert tarball_assignment < verification < extraction
    hashes = re.findall(r'PBS_SHA256="([0-9a-f]{64})"', script)
    assert len(hashes) == 2


def test_github_actions_are_commit_pinned() -> None:
    workflows = REPO_ROOT / ".github/workflows"
    action_refs: list[str] = []
    for path in workflows.glob("*.yml"):
        action_refs.extend(
            re.findall(r"^\s*uses:\s*[^\s@]+@([^\s#]+)", path.read_text(), re.MULTILINE)
        )

    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs)


def test_macos_package_always_requests_pinned_standalone_python() -> None:
    package_builder = (REPO_ROOT / "scripts/build-pkg.sh").read_text()
    runtime_builder = (REPO_ROOT / "scripts/build-sensor-venv.sh").read_text()

    assert 'PYTHON_BUILD_MODE=standalone bash "$SCRIPT_DIR/build-sensor-venv.sh"' in package_builder
    assert 'if [ "$SENSOR_PYTHON_MODE" != "standalone" ]; then' in package_builder
    assert 'PYTHON_BUILD_MODE="${PYTHON_BUILD_MODE:-standalone}"' in runtime_builder
    assert "arm64|universal)" not in runtime_builder
    assert "universal)" in runtime_builder
    assert "Standalone Python cannot be universal" in runtime_builder


def test_package_builders_sanitize_and_revalidate_the_python_payload() -> None:
    runtime_builder = (REPO_ROOT / "scripts/build-sensor-venv.sh").read_text()
    package_builder = (REPO_ROOT / "scripts/build-pkg.sh").read_text()

    runtime_install_match = re.search(
        r'"\$ENV_PYTHON" -m pip install\s*(?:\\\s*)?'
        r"--no-index\s*(?:\\\s*)?"
        r"--no-deps\s*(?:\\\s*)?"
        r'"\$SENSOR_WHEEL"',
        runtime_builder,
    )
    assert runtime_install_match is not None
    runtime_install = runtime_install_match.start()
    runtime_sanitization_match = re.search(
        r'bash "\$SCRIPT_DIR/sanitize-python-runtime\.sh"\s*(?:\\\s*)?'
        r"sanitize\s*(?:\\\s*)?"
        r'"\$PYTHON_DIR"\s+"\$REPO_ROOT"\s+"\$OUTPUT_DIR"',
        runtime_builder,
    )
    assert runtime_sanitization_match is not None
    runtime_sanitization = runtime_sanitization_match.start()
    runtime_smoke_import = runtime_builder.index(
        "'import aiohttp, aiosqlite, cryptography, fastapi, "
        "squirrelops_home_sensor, zeroconf'"
    )
    assert runtime_install < runtime_smoke_import < runtime_sanitization

    payload_copy = package_builder.index(
        'cp "$SCRIPT_DIR/pkg/uninstall.sh" "$SENSOR_INSTALL/uninstall.sh"'
    )
    staged_validation_match = re.search(
        r'bash "\$SCRIPT_DIR/sanitize-python-runtime\.sh"\s*(?:\\\s*)?'
        r"validate\s*(?:\\\s*)?"
        r'"\$SENSOR_INSTALL"\s+"\$REPO_ROOT"\s+"\$BUILD_DIR"',
        package_builder,
    )
    assert staged_validation_match is not None
    staged_validation = staged_validation_match.start()
    package_build = package_builder.index("# Step 5: Build component packages")
    assert payload_copy < staged_validation < package_build


def test_package_checks_do_not_regenerate_build_host_bytecode() -> None:
    package_builder = (REPO_ROOT / "scripts/build-pkg.sh").read_text()

    assert 'PYTHONDONTWRITEBYTECODE=1 "$SENSOR_PYTHON_BIN" -c' in package_builder
    assert 'PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" -c' in package_builder


def test_release_app_strips_and_rejects_embedded_build_host_paths() -> None:
    app_builder = (REPO_ROOT / "app/build-app.sh").read_text()
    font_registration = (
        REPO_ROOT / "app/Sources/SquirrelOpsHome/FontRegistration.swift"
    ).read_text()
    package_builder = (REPO_ROOT / "scripts/build-pkg.sh").read_text()

    assert '/usr/bin/strip -S "$binary"' in app_builder
    assert 'validate_no_build_host_paths "$APP_EXECUTABLE"' in app_builder
    assert 'validate_no_build_host_paths "$HELPER_PATH"' in app_builder
    assert "Bundle.module" not in font_registration
    assert "Bundle.main.executableURL" in font_registration
    assert 'grep -aFRl "$REPO_ROOT" "$APP_ROOT"' in package_builder


def test_macos_package_rejects_missing_or_unusable_helper() -> None:
    app_builder = (REPO_ROOT / "app/build-app.sh").read_text()
    package_builder = (REPO_ROOT / "scripts/build-pkg.sh").read_text()
    signer = (REPO_ROOT / "scripts/sign-app.sh").read_text()
    app_postinstall = (REPO_ROOT / "scripts/pkg/app-scripts/postinstall").read_text()
    sensor_postinstall = (REPO_ROOT / "scripts/pkg/postinstall").read_text()

    assert 'if [ ! -x "$BUILD_DIR/$HELPER_NAME" ]; then' in app_builder
    assert (
        "exit 1" in app_builder[app_builder.index('if [ ! -x "$BUILD_DIR/$HELPER_NAME" ]; then') :]
    )
    assert 'if [ ! -x "$HELPER_PATH" ]; then' in signer
    assert 'error "Required helper binary is missing or not executable' in signer
    assert 'validate_macho_arch "$HELPER_PATH" "$BUILD_ARCH"' in package_builder

    assert 'if [ ! -x "$HELPER_SRC" ]; then' in app_postinstall
    assert "exit 1" in app_postinstall[app_postinstall.index('if [ ! -x "$HELPER_SRC" ]; then') :]
    assert 'if ! launchctl bootstrap system "$PLIST_DEST"' in app_postinstall
    assert "verify_helper_rpc()" in app_postinstall
    assert '{"jsonrpc":"2.0","id":1,"method":"ping"}' in app_postinstall
    assert "result.protocol_version" in app_postinstall
    assert "arp_scan" in app_postinstall
    assert "virtual_ip" in app_postinstall
    assert "port_forward_isolation" in app_postinstall
    assert "service_scan" not in app_postinstall
    assert "dns_sniff" not in app_postinstall
    assert '/usr/bin/nc -zU "$SOCKET_PATH"' not in app_postinstall

    assert 'HELPER_BINARY="/Library/PrivilegedHelperTools/com.squirrelops.helper"' in (
        sensor_postinstall
    )
    assert "verify_helper_for_sensor_account()" in sensor_postinstall
    assert '/usr/bin/sudo -n -u "$SENSOR_USER" "$PYTHON_PATH"' in (sensor_postinstall)
    assert '"method": "ping"' in sensor_postinstall
    assert 'result.get("protocol_version") == 1' in sensor_postinstall
    assert '"arp_scan"' in sensor_postinstall
    assert '"virtual_ip"' in sensor_postinstall
    assert '"port_forward_isolation"' in sensor_postinstall
    assert '"service_scan"' not in sensor_postinstall
    assert '"dns_sniff"' not in sensor_postinstall
    assert '/usr/bin/nc -zU "$HELPER_SOCKET"' not in sensor_postinstall


def test_sensor_postinstall_fails_when_daemon_does_not_become_healthy() -> None:
    sensor_postinstall = (REPO_ROOT / "scripts/pkg/postinstall").read_text()

    assert 'if ! launchctl bootstrap system "$PLIST_DEST"' in sensor_postinstall
    assert "Failed to bootstrap sensor service" in sensor_postinstall
    assert (
        "Sensor did not become healthy within ${HEALTH_TIMEOUT_SECONDS}s"
        in sensor_postinstall
    )
    timeout_guard = sensor_postinstall.index(
        'if [ "$SENSOR_HEALTHY" -ne 1 ]; then'
    )
    assert "exit 1" in sensor_postinstall[timeout_guard:]


def test_release_version_has_one_authoritative_value() -> None:
    version = (REPO_ROOT / "VERSION").read_text().strip()
    pyproject = tomllib.loads((REPO_ROOT / "sensor/pyproject.toml").read_text(encoding="utf-8"))
    install_script = (REPO_ROOT / "scripts/install.sh").read_text()
    workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text()
    package_builder = (REPO_ROOT / "scripts/build-pkg.sh").read_text()
    sensor_postinstall = (REPO_ROOT / "scripts/pkg/postinstall").read_text()

    install_match = re.search(
        r'^SQUIRRELOPS_VERSION="([^"]+)"$',
        install_script,
        re.MULTILINE,
    )
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
    assert pyproject["project"]["version"] == version
    assert install_match is not None
    assert install_match.group(1) == version

    assert 'EXPECTED_TAG="v${VERSION}"' in workflow
    assert '[ "$GITHUB_REF_NAME" = "$EXPECTED_TAG" ]' in workflow
    assert 'sed -i "s/^version = ' not in workflow
    assert "SQUIRRELOPS_VERSION:" not in workflow

    assert 'VERSION="$(tr -d' in package_builder
    assert "SQUIRRELOPS_VERSION does not match authoritative VERSION" in (package_builder)
    assert package_builder.count('--version "$VERSION"') == 2
    assert 'printf \'%s\\n\' "$VERSION" > "$SENSOR_INSTALL/VERSION"' in package_builder
    assert 'INSTALLED_SENSOR_VERSION=$("$PYTHON_PATH"' in sensor_postinstall
    assert 'if [ "$INSTALLED_SENSOR_VERSION" != "$EXPECTED_SENSOR_VERSION" ]; then' in (
        sensor_postinstall
    )


def test_app_build_version_override_is_an_assertion_not_a_second_source() -> None:
    app_builder = (REPO_ROOT / "app/build-app.sh").read_text()

    assert 'VERSION="$(tr -d' in app_builder
    assert "App version override does not match authoritative VERSION" in app_builder
    assert 'VERSION="${SQUIRRELOPS_VERSION:-' not in app_builder


def test_package_advertises_only_the_validated_payload_architecture() -> None:
    package_builder = (REPO_ROOT / "scripts/build-pkg.sh").read_text()
    distribution = (REPO_ROOT / "scripts/pkg/distribution.xml").read_text()

    assert "arm64|x86_64)" in package_builder
    assert "universal)" in package_builder
    assert "Universal packages are unsupported" in package_builder
    assert 'validate_macho_arch "$APP_EXECUTABLE" "$BUILD_ARCH"' in package_builder
    assert 'validate_macho_arch "$HELPER_PATH" "$BUILD_ARCH"' in package_builder
    assert 'validate_macho_arch "$SENSOR_PYTHON_BIN" "$BUILD_ARCH"' in package_builder
    assert "s|__HOST_ARCH__|${BUILD_ARCH}|g" in package_builder

    assert 'hostArchitectures="__HOST_ARCH__"' in distribution
    assert 'hostArchitectures="arm64,x86_64"' not in distribution


def test_app_signer_requires_identity_for_release_but_not_local_builds(
    tmp_path: Path,
) -> None:
    app_bundle = tmp_path / "SquirrelOpsHome.app"
    helper = (
        app_bundle
        / "Contents/Library/LaunchServices/com.squirrelops.helper"
    )
    helper.parent.mkdir(parents=True)
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    helper.chmod(0o755)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_security = fake_bin / "security"
    fake_security.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    fake_security.chmod(0o755)

    signer = REPO_ROOT / "scripts/sign-app.sh"
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"

    local_result = subprocess.run(
        ["bash", str(signer), str(app_bundle), "Missing Identity"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert local_result.returncode == 0, local_result.stderr

    release_env = env | {"SQUIRRELOPS_RELEASE_BUILD": "1"}
    release_result = subprocess.run(
        ["bash", str(signer), str(app_bundle), "Missing Identity"],
        check=False,
        capture_output=True,
        text=True,
        env=release_env,
    )
    assert release_result.returncode != 0
    assert "Release builds require an available app signing identity" in (
        release_result.stdout + release_result.stderr
    )


def test_release_package_builder_fails_closed_on_all_trust_gates() -> None:
    package_builder = (REPO_ROOT / "scripts/build-pkg.sh").read_text()
    signer = (REPO_ROOT / "scripts/sign-app.sh").read_text()

    assert 'RELEASE_BUILD="${SQUIRRELOPS_RELEASE_BUILD:-0}"' in package_builder
    assert 'RELEASE_BUILD="${SQUIRRELOPS_RELEASE_BUILD:-0}"' in signer
    assert "Release builds require notarization credentials" in package_builder
    assert "Release builds cannot set SKIP_PKG_SIGNING=1" in package_builder
    assert "Release builds require an available app signing identity" in signer
    assert "Release builds require every sensor Mach-O binary to be signed" in (
        package_builder
    )
    assert "Release builds require an available installer signing identity" in (
        package_builder
    )

    notary_start = package_builder.index("xcrun notarytool submit")
    notary_end = package_builder.index("# Check if notarization was accepted")
    assert "|| true" not in package_builder[notary_start:notary_end]
    assert "Release notarization was not accepted" in package_builder
    assert 'xcrun stapler validate "$OUTPUT_DIR/$PKG_NAME"' in package_builder
    assert 'pkgutil --check-signature "$OUTPUT_DIR/$PKG_NAME"' in package_builder
    assert (
        'spctl --assess --type install --verbose=2 "$OUTPUT_DIR/$PKG_NAME"'
        in package_builder
    )
    assert 'codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE"' in (
        package_builder
    )
    assert 'codesign --verify --deep --strict --verbose=2 "$STAGED_APP_BUNDLE"' in (
        package_builder
    )
    assert 'codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE"' in signer


def test_release_workflow_requires_credentials_and_verifies_before_upload() -> None:
    workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text()

    assert 'SQUIRRELOPS_RELEASE_BUILD: "1"' in workflow
    assert "HAS_NOTARY_CREDENTIALS:" in workflow
    assert "Require release signing and notarization credentials" in workflow
    assert "Signing certificate secrets are required for release builds" in workflow
    assert "Notarization secrets are required for release builds" in workflow

    import_step = workflow.index("- name: Import signing certificates")
    select_xcode_step = workflow.index("- name: Select Xcode 16.2")
    assert "if:" not in workflow[import_step:select_xcode_step]

    verification = workflow.index("- name: Verify signed and notarized installer")
    upload = workflow.index("- name: Upload .pkg artifact")
    assert verification < upload
    verification_step = workflow[verification:upload]
    assert "codesign --verify --deep --strict --verbose=2" in verification_step
    assert "pkgutil --check-signature" in verification_step
    assert "xcrun stapler validate" in verification_step
    assert "spctl --assess --type install --verbose=2" in verification_step

    assert (
        "The signed and notarized installer is verified by macOS Gatekeeper "
        "before publication."
    ) in workflow
