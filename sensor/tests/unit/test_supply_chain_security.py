"""Regression tests for release and installer supply-chain controls."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tarfile
import tomllib
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: UniqueKeyLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


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


def test_workflows_are_valid_yaml_without_duplicate_keys() -> None:
    workflows = REPO_ROOT / ".github/workflows"
    for path in workflows.glob("*.yml"):
        with path.open(encoding="utf-8") as source:
            yaml.load(source, Loader=UniqueKeyLoader)


def test_workflows_have_no_duplicate_adjacent_nonblank_lines() -> None:
    workflows = REPO_ROOT / ".github/workflows"
    for path in workflows.glob("*.yml"):
        lines = path.read_text(encoding="utf-8").splitlines()
        duplicates = [
            (line_number, current.strip())
            for line_number, (current, following) in enumerate(
                zip(lines, lines[1:], strict=False),
                start=1,
            )
            if current.strip() and current.strip() == following.strip()
        ]
        assert not duplicates, f"{path}: duplicate adjacent lines: {duplicates}"


def test_macos_package_always_requests_pinned_standalone_python() -> None:
    package_builder = (REPO_ROOT / "scripts/build-pkg.sh").read_text()
    runtime_builder = (REPO_ROOT / "scripts/build-sensor-venv.sh").read_text()

    assert 'PYTHON_BUILD_MODE=standalone bash "$SCRIPT_DIR/build-sensor-venv.sh"' in package_builder
    assert 'if [ "$SENSOR_PYTHON_MODE" != "standalone" ]; then' in package_builder
    assert 'PYTHON_BUILD_MODE="${PYTHON_BUILD_MODE:-standalone}"' in runtime_builder
    assert "arm64|universal)" not in runtime_builder
    assert "universal)" in runtime_builder
    assert "Standalone Python cannot be universal" in runtime_builder


def test_release_container_build_inputs_are_digest_pinned() -> None:
    dockerfile = (REPO_ROOT / "sensor/Dockerfile").read_text(encoding="utf-8")
    image_references = re.findall(
        r"^FROM\s+([^\s]+)",
        dockerfile,
        re.MULTILINE,
    )

    external_references = [reference for reference in image_references if reference != "app"]
    assert len(external_references) == 2
    assert all(re.search(r"@sha256:[0-9a-f]{64}$", reference) for reference in external_references)
    assert image_references.count("app") == 2
    assert "ghcr.io/astral-sh/uv:0.10.2@" in dockerfile
    assert 'CMD ["/app/.venv/bin/python", "-m", "squirrelops_home_sensor"]' in (dockerfile)
    assert 'CMD ["uv", "run"' not in dockerfile

    workflow = (REPO_ROOT / ".github/workflows/release-sensor.yml").read_text()
    assert "no-cache: true" in workflow
    assert "cache-from:" not in workflow
    assert "cache-to:" not in workflow
    assert workflow.count("provenance: mode=max") == 1


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
        "'import aiohttp, aiosqlite, cryptography, fastapi, squirrelops_home_sensor, zeroconf'"
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


def test_macos_recovery_and_uninstall_paths_match_the_package_layout() -> None:
    guide = (REPO_ROOT / "docs/USER_GUIDE.md").read_text()
    preinstall = (REPO_ROOT / "scripts/pkg/app-scripts/preinstall").read_text()

    assert "### Recovering Legacy macOS Network State" in guide
    assert "/Library/SquirrelOps/sensor/data/squirrelops.db" in guide
    assert "pfctl -a com.apple/squirrelops -F all" in guide
    assert '/usr/sbin/arp -d "$IP" pub ifscope "$INTERFACE"' in guide
    assert '/sbin/ifconfig lo0 inet "$IP" -alias' in guide
    assert "docs/USER_GUIDE.md#recovering-legacy-macos-network-state" in preinstall
    assert "sudo bash /Library/SquirrelOps/sensor/uninstall.sh" in guide
    assert "sudo bash /Library/SquirrelOps/uninstall.sh" not in guide


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
    assert '/usr/bin/sudo -n -u "$SENSOR_USER" /usr/bin/env -i' in sensor_postinstall
    assert '"$PYTHON_PATH" -I - "$HELPER_SOCKET"' in sensor_postinstall
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
    assert "Sensor did not become healthy within ${HEALTH_TIMEOUT_SECONDS}s" in sensor_postinstall
    timeout_guard = sensor_postinstall.index('if [ "$SENSOR_HEALTHY" -ne 1 ]; then')
    assert "exit 1" in sensor_postinstall[timeout_guard:]


def test_component_versions_are_independently_authoritative() -> None:
    distribution_version = (REPO_ROOT / "VERSION").read_text().strip()
    app_version = (REPO_ROOT / "APP_VERSION").read_text().strip()
    pyproject = tomllib.loads((REPO_ROOT / "sensor/pyproject.toml").read_text(encoding="utf-8"))
    sensor_version = pyproject["project"]["version"]
    install_script = (REPO_ROOT / "scripts/install.sh").read_text()
    workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text()
    package_builder = (REPO_ROOT / "scripts/build-pkg.sh").read_text()
    sensor_postinstall = (REPO_ROOT / "scripts/pkg/postinstall").read_text()

    install_match = re.search(
        r'^SQUIRRELOPS_SENSOR_VERSION="([^"]+)"$',
        install_script,
        re.MULTILINE,
    )
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", distribution_version)
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", app_version)
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", sensor_version)
    assert install_match is not None
    assert install_match.group(1) == sensor_version

    assert "home-v${DISTRIBUTION_VERSION}" in workflow
    assert "sensor-v${SENSOR_VERSION}" in workflow
    assert "git diff --quiet" in workflow
    assert "APP_VERSION_VALUE" in workflow

    assert 'DISTRIBUTION_VERSION="$(tr -d' in package_builder
    assert 'APP_VERSION="$(tr -d' in package_builder
    assert "SENSOR_VERSION=$(" in package_builder
    assert package_builder.count('--version "$APP_VERSION"') == 1
    assert package_builder.count('--version "$SENSOR_VERSION"') == 1
    assert 'printf \'%s\\n\' "$SENSOR_VERSION" > "$SENSOR_INSTALL/VERSION"' in package_builder
    assert '"distribution_version": "$DISTRIBUTION_VERSION"' in package_builder
    assert '"app_version": "$APP_VERSION"' in package_builder
    assert '"sensor_version": "$SENSOR_VERSION"' in package_builder
    assert "INSTALLED_SENSOR_VERSION=$(isolated_python -c" in sensor_postinstall
    assert 'if [ "$INSTALLED_SENSOR_VERSION" != "$EXPECTED_SENSOR_VERSION" ]; then' in (
        sensor_postinstall
    )


def test_app_build_version_override_is_an_assertion_not_a_second_source() -> None:
    app_builder = (REPO_ROOT / "app/build-app.sh").read_text()

    assert 'APP_VERSION="$(tr -d' in app_builder
    assert 'DISTRIBUTION_VERSION="$(tr -d' in app_builder
    assert "App version override does not match authoritative APP_VERSION" in app_builder
    assert 'APP_VERSION="${SQUIRRELOPS_APP_VERSION:-' not in app_builder
    assert "<string>$APP_VERSION</string>" in app_builder
    assert "<string>$DISTRIBUTION_VERSION</string>" in app_builder


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
    helper = app_bundle / "Contents/Library/LaunchServices/com.squirrelops.helper"
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
    assert "Release builds require every sensor Mach-O binary to be signed" in (package_builder)
    assert "Release builds require an available installer signing identity" in (package_builder)

    notary_start = package_builder.index("xcrun notarytool submit")
    notary_end = package_builder.index("# Check if notarization was accepted")
    assert "|| true" not in package_builder[notary_start:notary_end]
    assert "Release notarization was not accepted" in package_builder
    assert 'xcrun stapler validate "$OUTPUT_DIR/$PKG_NAME"' in package_builder
    assert 'pkgutil --check-signature "$OUTPUT_DIR/$PKG_NAME"' in package_builder
    assert 'spctl --assess --type install --verbose=2 "$OUTPUT_DIR/$PKG_NAME"' in package_builder
    assert 'codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE"' in (package_builder)
    assert 'codesign --verify --deep --strict --verbose=2 "$STAGED_APP_BUNDLE"' in (package_builder)
    assert 'codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE"' in signer


def test_release_workflow_requires_credentials_and_verifies_before_upload() -> None:
    workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text()

    assert 'SQUIRRELOPS_RELEASE_BUILD: "1"' in workflow
    assert "APPLE_APPLICATION_CERTIFICATE_P12" in workflow
    assert "APPLE_INSTALLER_CERTIFICATE_P12" in workflow
    assert "secrets.APPLE_CERTIFICATE_P12 " not in workflow
    assert workflow.count("security import") == 2
    assert '"$RUNNER_TEMP/application-certificate.p12"' in workflow
    assert '"$RUNNER_TEMP/installer-certificate.p12"' in workflow
    assert '"$RUNNER_TEMP/application-key.pem"' in workflow
    assert '"$RUNNER_TEMP/installer-key.pem"' in workflow
    assert "Legacy RC2 PKCS#12 bundles are forbidden" in workflow
    assert "MAC: sha256" in workflow
    assert "AES-256-CBC" in workflow
    assert "certificate_key_hash" in workflow
    assert "private_key_hash" in workflow
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

    preparer = (REPO_ROOT / "scripts/prepare-release-assets.py").read_text(encoding="utf-8")
    assert "Gatekeeper validates the Developer ID signature" in preparer
    assert "notarization ticket, and" in preparer
    assert "stapled ticket" in preparer


def test_certificate_modernizer_uses_current_pkcs12_protection() -> None:
    modernizer = (REPO_ROOT / "scripts/modernize-apple-p12.sh").read_text(encoding="utf-8")

    assert "-keypbe AES-256-CBC" in modernizer
    assert "-certpbe AES-256-CBC" in modernizer
    assert "-macalg SHA256" in modernizer
    assert "-iter 200000" in modernizer
    assert "RC2" in modernizer
    assert "umask 077" in modernizer
    assert "mktemp -d" in modernizer
    assert "chmod 600" in modernizer
    assert "pass:" not in modernizer


def test_source_macos_installer_uses_only_the_frozen_local_project() -> None:
    installer = (REPO_ROOT / "scripts/install-macos.sh").read_text()

    assert 'REQUIRED_UV_VERSION="0.10.2"' in installer
    assert '"$SENSOR_DIR/uv.lock"' in installer
    assert "UV_PROJECT_ENVIRONMENT=" in installer
    assert "uv sync" in installer
    assert "--frozen" in installer
    assert "--no-dev" in installer
    assert "--no-editable" in installer
    assert "pip install" not in installer
    assert "PyPI" not in installer
    assert "squirrelops-home-sensor --quiet" not in installer

    # A source-only installer must never be served as a standalone web asset.
    assert not (REPO_ROOT / "site/public/install-macos.sh").exists()
    vercel = (REPO_ROOT / "site/vercel.json").read_text()
    assert "/install-macos.sh" not in vercel


def test_linux_release_installer_requires_an_immutable_image_digest() -> None:
    installer = (REPO_ROOT / "scripts/install.sh").read_text()

    assert 'SQUIRRELOPS_IMAGE_DIGEST="__RELEASE_IMAGE_DIGEST__"' in installer
    assert "Release installer is missing its pinned container digest" in installer
    assert 'IMAGE_REF="${IMAGE}@${SQUIRRELOPS_IMAGE_DIGEST}"' in installer
    assert 'docker pull --platform "$PLATFORM" "$IMAGE_REF"' in installer
    assert "image: ${IMAGE_REF}" in installer
    assert 'docker pull --platform "$PLATFORM" "$IMAGE:$SQUIRRELOPS_VERSION"' not in (installer)
    assert not (REPO_ROOT / "site/public/install.sh").exists()
    vercel = (REPO_ROOT / "site/vercel.json").read_text()
    assert '"/install.sh"' not in vercel


def _linux_installer_fixture(
    tmp_path: Path,
) -> tuple[Path, Path, dict[str, str]]:
    install_dir = tmp_path / "installed"
    script = tmp_path / "install.sh"
    source = (REPO_ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    source = source.replace(
        'SQUIRRELOPS_IMAGE_DIGEST="__RELEASE_IMAGE_DIGEST__"',
        f'SQUIRRELOPS_IMAGE_DIGEST="sha256:{"a" * 64}"',
    )
    source = source.replace(
        'INSTALL_DIR="/opt/squirrelops"',
        f'INSTALL_DIR="{install_dir}"',
    )
    script.write_text(source, encoding="utf-8")
    script.chmod(0o755)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_docker_log = tmp_path / "docker.log"
    commands = {
        "id": """#!/bin/bash
if [ "${1:-}" = "-u" ]; then
    printf '0\\n'
    exit 0
fi
exec /usr/bin/id "$@"
""",
        "docker": """#!/bin/bash
printf '%s\\n' "$*" >> "$FAKE_DOCKER_LOG"
exit 0
""",
        "uname": """#!/bin/bash
printf 'x86_64\\n'
""",
        "curl": """#!/bin/bash
exit 0
""",
        "sleep": """#!/bin/bash
exit 0
""",
        "ip": """#!/bin/bash
case "$*" in
  "-4 route show default")
    printf 'default via 10.23.4.1 dev enp3s0 proto dhcp src 10.23.4.19 metric 100\\n'
    ;;
  "-4 -o addr show dev enp3s0 scope global")
    printf '2: enp3s0 inet 10.23.4.19/24 brd 10.23.4.255 scope global enp3s0\\n'
    ;;
  *)
    exit 64
    ;;
esac
""",
    }
    for name, body in commands.items():
        command = fake_bin / name
        command.write_text(body, encoding="utf-8")
        command.chmod(0o755)

    env = os.environ | {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "FAKE_DOCKER_LOG": str(fake_docker_log),
    }
    return script, install_dir, env


def _compose_service_block(text: str, service: str) -> str:
    lines = text.splitlines()
    start = lines.index(f"  {service}:")
    block: list[str] = []
    for line in lines[start + 1 :]:
        if re.match(r"^  [A-Za-z0-9_.-]+:\s*$", line) or (line and not line[0].isspace()):
            break
        block.append(line)
    return "\n".join(block)


def test_linux_installer_detects_the_host_lan_without_a_guessed_default(
    tmp_path: Path,
) -> None:
    script, install_dir, env = _linux_installer_fixture(tmp_path)

    result = subprocess.run(
        ["bash", str(script)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode == 0, result.stderr
    compose = (install_dir / "docker-compose.yml").read_text(encoding="utf-8")
    assert 'SQUIRRELOPS_LAN_SUBNET: "10.23.4.0/24"' in compose
    assert 'SQUIRRELOPS_SUBNET: "10.23.4.0/24"' in compose
    assert "192.168.1.0/24" not in compose
    assert "Using LAN subnet 10.23.4.0/24" in result.stdout


def test_linux_upgrade_migrates_legacy_privileges_and_preserves_settings(
    tmp_path: Path,
) -> None:
    script, install_dir, env = _linux_installer_fixture(tmp_path)
    install_dir.mkdir()
    compose_path = install_dir / "docker-compose.yml"
    compose_path.write_text(
        """services:
  sensor:
    image: ghcr.io/rocketweb/squirrelops-sensor:1.1.14
    network_mode: host
    user: "0:0"
    cap_add:
      - NET_RAW
      - NET_ADMIN
    environment:
      SQUIRRELOPS_DATA_DIR: /app/data
      SQUIRRELOPS_PORT: "9443"
      SQUIRRELOPS_SUBNET: "10.55.8.19/24"
      SQUIRRELOPS_PROFILE: "full"
""",
        encoding="utf-8",
    )

    result = subprocess.run(
        ["bash", str(script), "--upgrade"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode == 0, result.stderr
    compose = compose_path.read_text(encoding="utf-8")
    sensor_block = _compose_service_block(compose, "sensor")
    helper_block = _compose_service_block(compose, "network-helper")
    assert "network_mode: host" not in sensor_block
    assert "NET_RAW" not in sensor_block
    assert "NET_ADMIN" not in sensor_block
    assert 'user: "10001:10001"' in sensor_block
    assert "cap_drop:\n      - ALL" in sensor_block
    assert "read_only: true" in sensor_block
    assert "no-new-privileges:true" in sensor_block
    assert "helper_socket:/run/squirrelops:ro" in sensor_block
    assert "network_mode: host" in helper_block
    assert "NET_RAW" in helper_block
    assert "NET_ADMIN" in helper_block
    assert 'SQUIRRELOPS_PORT: "9443"' in compose
    assert 'SQUIRRELOPS_SUBNET: "10.55.8.0/24"' in compose
    assert 'SQUIRRELOPS_LAN_SUBNET: "10.55.8.0/24"' in compose
    assert 'SQUIRRELOPS_PROFILE: "full"' in compose
    assert '"9443:9443"' in compose
    assert "Migrating the legacy root/host-network sensor" in result.stdout
    assert not list(install_dir.glob(".docker-compose.previous.*"))


def test_linux_upgrade_restores_legacy_compose_after_failed_health_check(
    tmp_path: Path,
) -> None:
    script, install_dir, env = _linux_installer_fixture(tmp_path)
    install_dir.mkdir()
    compose_path = install_dir / "docker-compose.yml"
    legacy_compose = """services:
  sensor:
    image: ghcr.io/rocketweb/squirrelops-sensor:1.1.14
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN
    environment:
      SQUIRRELOPS_PORT: "8443"
      SQUIRRELOPS_SUBNET: "10.55.8.0/24"
"""
    compose_path.write_text(legacy_compose, encoding="utf-8")
    fake_curl = Path(env["PATH"].split(":", 1)[0]) / "curl"
    fake_curl.write_text("#!/bin/bash\nexit 1\n", encoding="utf-8")
    fake_curl.chmod(0o755)

    result = subprocess.run(
        ["bash", str(script), "--upgrade"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode != 0
    assert compose_path.read_text(encoding="utf-8") == legacy_compose
    assert "previous compose configuration was restored" in result.stderr
    assert not list(install_dir.glob(".docker-compose.previous.*"))


def test_release_asset_preparer_renders_and_checksums_pinned_inputs(
    tmp_path: Path,
) -> None:
    version = (REPO_ROOT / "VERSION").read_text().strip()
    package = tmp_path / f"SquirrelOpsHome-{version}.pkg"
    package.write_bytes(b"signed-package-placeholder")
    output_dir = tmp_path / "release-assets"
    root_manifest = b'{"manifests":[],"schemaVersion":2}'
    digest_hex = hashlib.sha256(root_manifest).hexdigest()
    digest = f"sha256:{digest_hex}"
    oci_source = tmp_path / "sensor.oci.tar"
    oci_layout = tmp_path / "oci-layout"
    oci_index = tmp_path / "index.json"
    oci_blob = tmp_path / digest_hex
    oci_layout.write_text('{"imageLayoutVersion":"1.0.0"}', encoding="utf-8")
    oci_index.write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.index.v1+json",
                        "digest": digest,
                        "size": len(root_manifest),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    oci_blob.write_bytes(root_manifest)
    with tarfile.open(oci_source, "w") as archive:
        archive.add(oci_layout, arcname="oci-layout")
        archive.add(oci_index, arcname="index.json")
        archive.add(oci_blob, arcname=f"blobs/sha256/{digest_hex}")
    commit = "b" * 40
    command = [
        "python3",
        str(REPO_ROOT / "scripts/prepare-release-assets.py"),
        "--package",
        str(package),
        "--tag",
        f"home-v{version}",
        "--commit",
        commit,
        "--repository",
        "rocketweb/squirrelops-home",
        "--output",
        str(output_dir),
    ]

    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    check = subprocess.run(
        ["shasum", "-a", "256", "-c", "SHA256SUMS"],
        cwd=output_dir,
        check=False,
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stderr

    metadata = json.loads((output_dir / "release-metadata.json").read_text())
    assert metadata["schema_version"] == 2
    assert metadata["release"]["tag"] == f"home-v{version}"
    assert metadata["release"]["distribution_version"] == version
    assert metadata["release"]["commit"] == commit
    verification_path = output_dir / "RELEASE-VERIFICATION.md"
    verification = verification_path.read_text(encoding="utf-8")
    verification_sha = hashlib.sha256(verification_path.read_bytes()).hexdigest()
    assert metadata["release"]["verification_artifact"] == verification_path.name
    assert metadata["release"]["verification_sha256"] == verification_sha
    assert metadata["release"]["verification_url"].endswith("/RELEASE-VERIFICATION.md")
    assert f"Release commit: `{commit}`" in verification
    assert "canonical release-notes and verification document" in verification
    assert "GitHub's release title and description are editable" in verification
    assert "gh release verify" in verification
    assert "gh attestation verify RELEASE-VERIFICATION.md" in verification
    assert f"--signer-digest {commit}" in verification
    assert f"--source-digest {commit}" in verification
    assert "It is not\npublished automatically" in verification
    expected_package_sha = hashlib.sha256((output_dir / package.name).read_bytes()).hexdigest()
    assert metadata["macos"]["sha256"] == expected_package_sha
    assert metadata["macos"]["app_version"] == (REPO_ROOT / "APP_VERSION").read_text().strip()
    assert (
        metadata["macos"]["sensor_version"]
        == tomllib.loads((REPO_ROOT / "sensor/pyproject.toml").read_text(encoding="utf-8"))[
            "project"
        ]["version"]
    )
    assert metadata["macos"]["sensor_api_protocol"] == 2
    assert "docker" not in metadata
    cask_path = output_dir / "squirrelops-home.rb"
    cask = cask_path.read_text(encoding="utf-8")
    package_url = (
        "https://github.com/rocketweb/squirrelops-home/releases/download/"
        f"home-v{version}/{package.name}"
    )
    assert f'version "{version}"' in cask
    assert f'sha256 "{expected_package_sha}"' in cask
    assert (
        'url "https://github.com/rocketweb/squirrelops-home/releases/'
        'download/home-v#{version}/SquirrelOpsHome-#{version}.pkg",'
    ) in cask
    assert 'pkg "SquirrelOpsHome-#{version}.pkg"' in cask
    assert "depends_on arch: :arm64" in cask
    assert "depends_on macos: :sonoma" in cask
    assert 'homepage "https://www.squirrelops.io/"' in cask
    assert 'executable: "/Library/SquirrelOps/sensor/uninstall.sh"' in cask
    assert 'args:       ["--preserve-data"]' in cask
    assert "sudo:       true" in cask
    assert '"com.squirrelops.home.app"' in cask
    assert '"com.squirrelops.home.sensor"' in cask
    assert metadata["homebrew"]["cask_artifact"] == "squirrelops-home.rb"
    assert metadata["homebrew"]["cask_sha256"] == hashlib.sha256(cask_path.read_bytes()).hexdigest()
    assert metadata["homebrew"]["cask_url"] == (
        "https://github.com/rocketweb/squirrelops-home/releases/download/"
        f"home-v{version}/squirrelops-home.rb"
    )
    assert metadata["homebrew"]["url"] == package_url
    assert metadata["homebrew"]["sha256"] == expected_package_sha
    checksums = (output_dir / "SHA256SUMS").read_text()
    assert "squirrelops-home.rb" in checksums
    assert "install.sh" not in checksums
    assert "squirrelops-sensor-" not in checksums
    assert f"{verification_sha}  RELEASE-VERIFICATION.md" in checksums

    repeat_output = tmp_path / "repeat-assets"
    repeat_command = [*command[:-1], str(repeat_output)]
    repeat = subprocess.run(
        repeat_command,
        check=False,
        capture_output=True,
        text=True,
    )
    assert repeat.returncode == 0, repeat.stderr
    assert {path.name: path.read_bytes() for path in output_dir.iterdir()} == {
        path.name: path.read_bytes() for path in repeat_output.iterdir()
    }


def test_sensor_release_assets_are_independent_and_digest_pinned(
    tmp_path: Path,
) -> None:
    sensor_version = tomllib.loads(
        (REPO_ROOT / "sensor/pyproject.toml").read_text(encoding="utf-8")
    )["project"]["version"]
    root_manifest = b'{"manifests":[],"schemaVersion":2}'
    digest_hex = hashlib.sha256(root_manifest).hexdigest()
    digest = f"sha256:{digest_hex}"
    oci_source = tmp_path / "sensor.oci.tar"
    oci_layout = tmp_path / "oci-layout"
    oci_index = tmp_path / "index.json"
    oci_blob = tmp_path / digest_hex
    oci_layout.write_text('{"imageLayoutVersion":"1.0.0"}', encoding="utf-8")
    oci_index.write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.index.v1+json",
                        "digest": digest,
                        "size": len(root_manifest),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    oci_blob.write_bytes(root_manifest)
    with tarfile.open(oci_source, "w") as archive:
        archive.add(oci_layout, arcname="oci-layout")
        archive.add(oci_index, arcname="index.json")
        archive.add(oci_blob, arcname=f"blobs/sha256/{digest_hex}")

    output_dir = tmp_path / "sensor-release-assets"
    commit = "c" * 40
    result = subprocess.run(
        [
            "python3",
            str(REPO_ROOT / "scripts/prepare-sensor-release-assets.py"),
            "--oci-archive",
            str(oci_source),
            "--docker-digest",
            digest,
            "--tag",
            f"sensor-v{sensor_version}",
            "--commit",
            commit,
            "--repository",
            "rocketweb/squirrelops-home",
            "--output",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    check = subprocess.run(
        ["shasum", "-a", "256", "-c", "SHA256SUMS"],
        cwd=output_dir,
        check=False,
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stderr
    installer = (output_dir / "install.sh").read_text(encoding="utf-8")
    assert "__RELEASE_IMAGE_DIGEST__" not in installer
    assert f'SQUIRRELOPS_IMAGE_DIGEST="{digest}"' in installer
    metadata = json.loads((output_dir / "sensor-release-metadata.json").read_text(encoding="utf-8"))
    assert metadata["release"] == {
        "commit": commit,
        "repository": "rocketweb/squirrelops-home",
        "sensor_api_protocol": 2,
        "sensor_version": sensor_version,
        "tag": f"sensor-v{sensor_version}",
    }
    assert metadata["container"]["digest"] == digest
    assert "app_version" not in json.dumps(metadata)
    assert "distribution_version" not in json.dumps(metadata)


def test_release_workflow_is_manual_main_pinned_and_approval_gated() -> None:
    home_workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text()
    sensor_workflow = (REPO_ROOT / ".github/workflows/release-sensor.yml").read_text()

    for workflow in (home_workflow, sensor_workflow):
        assert "workflow_dispatch:" in workflow
        assert "push:" not in workflow.split("permissions:", 1)[0]
        assert "commit_sha:" in workflow
        assert "GITHUB_RUN_ATTEMPT" in workflow
        assert "$GITHUB_RUN_ID" in workflow
        assert "$GITHUB_ACTOR_ID" in workflow
        assert "refs/heads/main" in workflow
        assert "EXPECTED_COMMIT: ${{ inputs.commit_sha }}" in workflow
        assert "ref: ${{ needs.verify-release.outputs.commit_sha }}" in workflow
        assert workflow.count("environment: release") >= 2
        assert workflow.count("bash scripts/check-release-controls.sh") >= 2
        assert "actions: read" in workflow
        assert "continue-on-error: true" not in workflow
        assert "PYPI_API_TOKEN" not in workflow
        assert "push origin HEAD:main" not in workflow

    assert "home-v${DISTRIBUTION_VERSION}" in home_workflow
    assert 'APP_TAG="app-v${APP_VERSION_VALUE}"' in home_workflow
    assert 'SENSOR_TAG="sensor-v${SENSOR_VERSION}"' in home_workflow
    assert "docker/build-push-action@" not in home_workflow
    assert "sensor-v${SENSOR_VERSION}" in sensor_workflow
    assert "--latest=false" in sensor_workflow
    assert "docker/build-push-action@" in sensor_workflow
    assert "check-linux-release-boundary.py" in sensor_workflow
    assert "git/ref/tags/" in (REPO_ROOT / "scripts/check-release-controls.sh").read_text(
        encoding="utf-8"
    )


def test_checked_in_release_policy_has_a_fail_closed_schema() -> None:
    policy = json.loads((REPO_ROOT / ".github/release-policy.json").read_text(encoding="utf-8"))
    assert policy["schema_version"] == 3
    assert set(policy) == {
        "schema_version",
        "linux_release",
        "tag_bypass_user_id",
        "release_environment",
        "main_ruleset",
        "tag_ruleset",
    }
    assert policy["linux_release"] == {
        "mode": "blocked",
        "reviewed_at": None,
    }
    assert isinstance(policy["tag_bypass_user_id"], int)
    assert policy["tag_bypass_user_id"] >= 0
    assert set(policy["release_environment"]) == {
        "id",
        "name",
        "updated_at",
        "reviewer",
    }
    assert isinstance(policy["release_environment"]["id"], int)
    assert policy["release_environment"]["id"] >= 0
    assert policy["release_environment"]["name"] == "release"
    reviewer = policy["release_environment"]["reviewer"]
    assert set(reviewer) == {"type", "id"}
    assert reviewer["type"] in (None, "User")
    assert isinstance(reviewer["id"], int)
    assert reviewer["id"] >= 0
    assert policy["release_environment"]["updated_at"] is None or re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z",
        policy["release_environment"]["updated_at"],
    )
    assert set(policy["main_ruleset"]) == {
        "id",
        "updated_at",
        "required_check_integration_id",
    }
    assert isinstance(policy["main_ruleset"]["id"], int)
    assert policy["main_ruleset"]["id"] >= 0
    assert isinstance(
        policy["main_ruleset"]["required_check_integration_id"],
        int,
    )
    assert policy["main_ruleset"]["required_check_integration_id"] == 15368
    assert policy["main_ruleset"]["updated_at"] is None or re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z",
        policy["main_ruleset"]["updated_at"],
    )
    assert set(policy["tag_ruleset"]) == {"id", "updated_at"}
    assert isinstance(policy["tag_ruleset"]["id"], int)
    assert policy["tag_ruleset"]["id"] >= 0
    assert policy["tag_ruleset"]["updated_at"] is None or re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z",
        policy["tag_ruleset"]["updated_at"],
    )


def test_linux_release_boundary_is_explicitly_blocked() -> None:
    checker = REPO_ROOT / "scripts/check-linux-release-boundary.py"
    result = subprocess.run(
        [
            "python3",
            str(checker),
            str(REPO_ROOT / ".github/release-policy.json"),
            str(REPO_ROOT),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "Linux release is blocked" in result.stderr
    assert "NET_RAW/NET_ADMIN" in result.stderr


def test_linux_boundary_requires_a_safe_tree_for_each_reviewed_mode(
    tmp_path: Path,
) -> None:
    checker = REPO_ROOT / "scripts/check-linux-release-boundary.py"
    reviewed_at = "2026-07-24T20:00:00Z"
    policy_path = tmp_path / "policy.json"
    install_path = tmp_path / "scripts/install.sh"
    compose_path = tmp_path / "sensor/docker-compose.yml"
    release_workflow = tmp_path / ".github/workflows/release.yml"
    install_path.parent.mkdir(parents=True)
    compose_path.parent.mkdir(parents=True)
    release_workflow.parent.mkdir(parents=True)
    safe_compose = """services:
  sensor:
    image: sensor@example
    user: "10001:10001"
    cap_drop:
      - ALL
    read_only: true
    security_opt:
      - no-new-privileges:true
    volumes:
      - sensor_data:/app/data
      - helper_socket:/run/squirrelops:ro
  network-helper:
    image: helper@example
    network_mode: host
    command:
      - /app/.venv/bin/python
      - -m
      - squirrelops_home_sensor.privileged.linux_sidecar
    cap_drop:
      - ALL
    cap_add:
      - NET_RAW
      - NET_ADMIN
    read_only: true
    security_opt:
      - no-new-privileges:true

volumes:
  sensor_data:
  helper_socket:
"""
    install_path.write_text(safe_compose, encoding="utf-8")
    compose_path.write_text(safe_compose, encoding="utf-8")
    policy = {
        "schema_version": 3,
        "linux_release": {
            "mode": "constrained-sidecar-reviewed",
            "reviewed_at": reviewed_at,
        },
    }
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    constrained = subprocess.run(
        ["python3", str(checker), str(policy_path), str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert constrained.returncode == 0, constrained.stderr

    install_path.write_text(
        safe_compose.replace(
            "    image: sensor@example\n",
            "    image: sensor@example\n    network_mode: host\n",
            1,
        ),
        encoding="utf-8",
    )
    unsafe = subprocess.run(
        ["python3", str(checker), str(policy_path), str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert unsafe.returncode != 0
    assert "host-level network authority directly" in unsafe.stderr

    policy["linux_release"] = {
        "mode": "macos-only-reviewed",
        "reviewed_at": reviewed_at,
    }
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    release_workflow.write_text(
        "name: Release\njobs:\n  build-macos-pkg:\n    runs-on: macos-15\n",
        encoding="utf-8",
    )
    macos_only = subprocess.run(
        ["python3", str(checker), str(policy_path), str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert macos_only.returncode == 0, macos_only.stderr

    release_workflow.write_text(
        "name: Release\njobs:\n  build-linux-container:\n",
        encoding="utf-8",
    )
    lingering_linux = subprocess.run(
        ["python3", str(checker), str(policy_path), str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert lingering_linux.returncode != 0
    assert "still contains Linux publication paths" in lingering_linux.stderr


def test_remote_release_control_checker_is_complete_and_fail_closed(
    tmp_path: Path,
) -> None:
    checker = REPO_ROOT / "scripts/check-release-controls.sh"
    checker_text = checker.read_text(encoding="utf-8")
    assert "immutable-releases" in checker_text
    assert "environments/release" in checker_text
    assert "can_admins_bypass" in checker_text
    assert "prevent_self_review" in checker_text
    assert "protected_branches" in checker_text
    assert "tag_ruleset.updated_at" in checker_text
    assert "tag_bypass_user_id" in checker_text
    assert "release_environment.reviewer.type" in checker_text
    assert "release_environment.updated_at" in checker_text
    assert "release_environment.id" in checker_text
    assert ".github/workflows/release.yml" in checker_text
    assert ".github/workflows/release-sensor.yml" in checker_text
    assert "actions/runs/${WORKFLOW_RUN_ID}/approvals" in checker_text
    assert "($decisions | length >= 1)" in checker_text
    assert "and all(" in checker_text
    assert ".run_attempt == 1" in checker_text
    assert '.event == "workflow_dispatch"' in checker_text
    assert "main_ruleset.id" in checker_text
    assert "main_ruleset.required_check_integration_id" in checker_text
    assert ".bypass_actors" not in checker_text
    assert 'index("update")' in checker_text
    assert 'index("non_fast_forward")' in checker_text
    assert "required_approving_review_count" in checker_text
    assert "required_status_checks" in checker_text
    assert ".integration_id == $check_integration_id" in checker_text
    assert "Verify release and package controls" in checker_text
    assert "Supply Chain CI / Verify release and package controls" not in checker_text
    assert "Only the pinned tag-bypass User may dispatch a release" in checker_text
    assert "fresh run lacks exact approval" in checker_text
    assert "verification.verified == true" in checker_text
    assert checker_text.count('.current_user_can_bypass == "never"') == 2
    assert ".current_user_can_bypass //" not in checker_text
    for required_rule in ("creation", "update", "deletion"):
        assert f'index("{required_rule}")' in checker_text
    main_ruleset_check = checker_text.split(
        'MAIN_RULESET_JSON="$CONTROL_DIR/main-ruleset.json"',
        1,
    )[1]
    assert 'index("update")' not in main_ruleset_check

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_gh = fake_bin / "gh"
    fake_gh.write_text(
        """#!/bin/bash
set -eu
case "$*" in
  *git/ref/tags/home-v1.2.3*) printf '%s\\n' \
    '{"object":{"type":"tag","sha":"cccccccccccccccccccccccccccccccccccccccc"}}' ;;
  *git/tags/cccccccccccccccccccccccccccccccccccccccc*) printf '%s\\n' \
    '{"object":{"type":"commit"},"verification":{"verified":true,"reason":"valid"}}' ;;
  *immutable-releases*) printf '%s\\n' true ;;
  *environments/release*) cat "$FAKE_ENVIRONMENT_JSON" ;;
  *actions/runs/9001/approvals*) cat "$FAKE_APPROVALS_JSON" ;;
  *actions/runs/9001*) cat "$FAKE_RUN_JSON" ;;
  *rulesets/42*) cat "$FAKE_RULESET_JSON" ;;
  *rulesets/43*) cat "$FAKE_MAIN_RULESET_JSON" ;;
  *) exit 64 ;;
esac
""",
        encoding="utf-8",
    )
    fake_gh.chmod(0o755)
    fake_sleep = fake_bin / "sleep"
    fake_sleep.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_sleep.chmod(0o755)

    environment_path = tmp_path / "environment.json"
    environment = {
        "id": 8080,
        "name": "release",
        "updated_at": "2026-07-24T20:00:00Z",
        "can_admins_bypass": False,
        "protection_rules": [
            {
                "type": "required_reviewers",
                "prevent_self_review": True,
                "reviewers": [
                    {
                        "type": "User",
                        "reviewer": {"id": 2718, "login": "reviewer"},
                    }
                ],
            }
        ],
        "deployment_branch_policy": {"protected_branches": True},
    }
    environment_path.write_text(json.dumps(environment), encoding="utf-8")

    ruleset_path = tmp_path / "ruleset.json"
    reviewed_at = "2026-07-24T20:00:00Z"
    ruleset_path.write_text(
        json.dumps(
            {
                "id": 42,
                "source_type": "Repository",
                "source": "rocketweb/squirrelops-home",
                "target": "tag",
                "enforcement": "active",
                "updated_at": reviewed_at,
                "current_user_can_bypass": "never",
                "conditions": {
                    "ref_name": {
                        "include": [
                            "refs/tags/home-v*",
                            "refs/tags/app-v*",
                            "refs/tags/sensor-v*",
                        ],
                        "exclude": [],
                    }
                },
                "rules": [
                    {"type": "creation"},
                    {"type": "update"},
                    {"type": "deletion"},
                ],
            }
        ),
        encoding="utf-8",
    )
    main_ruleset_path = tmp_path / "main-ruleset.json"
    main_ruleset_path.write_text(
        json.dumps(
            {
                "id": 43,
                "source_type": "Repository",
                "source": "rocketweb/squirrelops-home",
                "target": "branch",
                "enforcement": "active",
                "updated_at": reviewed_at,
                "current_user_can_bypass": "never",
                "conditions": {
                    "ref_name": {
                        "include": ["refs/heads/main"],
                        "exclude": [],
                    }
                },
                "rules": [
                    {"type": "deletion"},
                    {"type": "non_fast_forward"},
                    {
                        "type": "pull_request",
                        "parameters": {
                            "required_approving_review_count": 1,
                            "dismiss_stale_reviews_on_push": True,
                            "require_last_push_approval": True,
                            "required_review_thread_resolution": True,
                        },
                    },
                    {
                        "type": "required_status_checks",
                        "parameters": {
                            "strict_required_status_checks_policy": True,
                            "required_status_checks": [
                                {
                                    "context": ("Verify release and package controls"),
                                    "integration_id": 15368,
                                }
                            ],
                        },
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    policy_path = tmp_path / "release-policy.json"
    safe_compose = """services:
  sensor:
    image: sensor@example
    user: "10001:10001"
    cap_drop:
      - ALL
    read_only: true
    security_opt:
      - no-new-privileges:true
    volumes:
      - sensor_data:/app/data
      - helper_socket:/run/squirrelops:ro
  network-helper:
    image: helper@example
    network_mode: host
    command:
      - /app/.venv/bin/python
      - -m
      - squirrelops_home_sensor.privileged.linux_sidecar
    cap_drop:
      - ALL
    cap_add:
      - NET_RAW
      - NET_ADMIN
    read_only: true
    security_opt:
      - no-new-privileges:true

volumes:
  sensor_data:
  helper_socket:
"""
    test_install = tmp_path / "scripts/install.sh"
    test_compose = tmp_path / "sensor/docker-compose.yml"
    test_install.parent.mkdir(parents=True)
    test_compose.parent.mkdir(parents=True)
    test_install.write_text(safe_compose, encoding="utf-8")
    test_compose.write_text(safe_compose, encoding="utf-8")
    policy = {
        "schema_version": 3,
        "linux_release": {
            "mode": "constrained-sidecar-reviewed",
            "reviewed_at": reviewed_at,
        },
        "tag_bypass_user_id": 314,
        "release_environment": {
            "id": 8080,
            "name": "release",
            "updated_at": reviewed_at,
            "reviewer": {"type": "User", "id": 2718},
        },
        "main_ruleset": {
            "id": 43,
            "updated_at": reviewed_at,
            "required_check_integration_id": 15368,
        },
        "tag_ruleset": {"id": 42, "updated_at": reviewed_at},
    }
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    run_path = tmp_path / "run.json"
    run_path.write_text(
        json.dumps(
            {
                "id": 9001,
                "run_attempt": 1,
                "event": "workflow_dispatch",
                "head_branch": "main",
                "path": ".github/workflows/release.yml",
                "actor": {"id": 314, "type": "User"},
                "triggering_actor": {"id": 314, "type": "User"},
            }
        ),
        encoding="utf-8",
    )
    approvals_path = tmp_path / "approvals.json"
    approvals_path.write_text(
        json.dumps(
            [
                {
                    "state": "approved",
                    "user": {"id": 2718, "type": "User"},
                    "environments": [{"id": 8080, "name": "release"}],
                },
                {
                    "state": "approved",
                    "user": {"id": 2718, "type": "User"},
                    "environments": [{"id": 8080, "name": "release"}],
                },
            ]
        ),
        encoding="utf-8",
    )
    env = os.environ | {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "FAKE_ENVIRONMENT_JSON": str(environment_path),
        "FAKE_RULESET_JSON": str(ruleset_path),
        "FAKE_MAIN_RULESET_JSON": str(main_ruleset_path),
        "FAKE_RUN_JSON": str(run_path),
        "FAKE_APPROVALS_JSON": str(approvals_path),
    }

    checker_command = [
        "bash",
        str(checker),
        "rocketweb/squirrelops-home",
        "home-v1.2.3",
        str(policy_path),
        "9001",
        "1",
        "314",
        str(tmp_path),
    ]
    good = subprocess.run(
        checker_command,
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert good.returncode == 0, good.stderr

    for ruleset_fixture, expected_error in (
        (
            ruleset_path,
            "component-tag ruleset changed from its reviewed configuration",
        ),
        (
            main_ruleset_path,
            "main ruleset does not enforce reviewed branch protections",
        ),
    ):
        safe_ruleset = json.loads(ruleset_fixture.read_text(encoding="utf-8"))
        for bypass_value in ("always", "pull_requests_only", None):
            unsafe_ruleset = dict(safe_ruleset)
            if bypass_value is None:
                unsafe_ruleset.pop("current_user_can_bypass")
            else:
                unsafe_ruleset["current_user_can_bypass"] = bypass_value
            ruleset_fixture.write_text(
                json.dumps(unsafe_ruleset),
                encoding="utf-8",
            )
            bypassable = subprocess.run(
                checker_command,
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            assert bypassable.returncode != 0
            assert expected_error in bypassable.stderr.lower()
        ruleset_fixture.write_text(
            json.dumps(safe_ruleset),
            encoding="utf-8",
        )

    approvals = json.loads(approvals_path.read_text(encoding="utf-8"))
    approvals.append(
        {
            "state": "approved",
            "user": {"id": 9999, "type": "User"},
            "environments": [{"id": 8080, "name": "release"}],
        }
    )
    approvals_path.write_text(json.dumps(approvals), encoding="utf-8")
    mismatched_approver = subprocess.run(
        [
            "bash",
            str(checker),
            "rocketweb/squirrelops-home",
            "home-v1.2.3",
            str(policy_path),
            "9001",
            "1",
            "314",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert mismatched_approver.returncode != 0
    assert "lacks exact approval" in mismatched_approver.stderr

    approvals[-1] = {
        "state": "rejected",
        "user": {"id": 2718, "type": "User"},
        "environments": [{"id": 8080, "name": "release"}],
    }
    approvals_path.write_text(json.dumps(approvals), encoding="utf-8")
    rejected_decision = subprocess.run(
        [
            "bash",
            str(checker),
            "rocketweb/squirrelops-home",
            "home-v1.2.3",
            str(policy_path),
            "9001",
            "1",
            "314",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert rejected_decision.returncode != 0
    assert "lacks exact approval" in rejected_decision.stderr
    approvals_path.write_text(json.dumps(approvals[:-1]), encoding="utf-8")

    rerun = subprocess.run(
        [
            "bash",
            str(checker),
            "rocketweb/squirrelops-home",
            "home-v1.2.3",
            str(policy_path),
            "9001",
            "2",
            "314",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert rerun.returncode != 0
    assert "reruns are forbidden" in rerun.stderr

    policy["tag_ruleset"]["updated_at"] = "2026-07-24T20:01:00Z"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    changed_policy = subprocess.run(
        [
            "bash",
            str(checker),
            "rocketweb/squirrelops-home",
            "home-v1.2.3",
            str(policy_path),
            "9001",
            "1",
            "314",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert changed_policy.returncode != 0
    assert "bypass actors were independently reviewed" in changed_policy.stderr

    policy["tag_ruleset"]["updated_at"] = reviewed_at
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    environment["can_admins_bypass"] = True
    environment_path.write_text(json.dumps(environment), encoding="utf-8")
    unsafe = subprocess.run(
        [
            "bash",
            str(checker),
            "rocketweb/squirrelops-home",
            "home-v1.2.3",
            str(policy_path),
            "9001",
            "1",
            "314",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert unsafe.returncode != 0
    assert "disallow administrator bypass" in unsafe.stderr

    environment["can_admins_bypass"] = False
    environment_path.write_text(json.dumps(environment), encoding="utf-8")
    main_ruleset = json.loads(main_ruleset_path.read_text(encoding="utf-8"))
    release_check = main_ruleset["rules"][-1]["parameters"]["required_status_checks"][0]
    for untrusted_integration_id in (None, 9999):
        release_check["integration_id"] = untrusted_integration_id
        main_ruleset_path.write_text(
            json.dumps(main_ruleset),
            encoding="utf-8",
        )
        spoofable_check = subprocess.run(
            [
                "bash",
                str(checker),
                "rocketweb/squirrelops-home",
                "home-v1.2.3",
                str(policy_path),
                "9001",
                "1",
                "314",
                str(tmp_path),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        assert spoofable_check.returncode != 0
        assert "does not enforce reviewed branch protections" in (spoofable_check.stderr)


def test_release_workflow_drafts_attests_and_publishes_last() -> None:
    home = (REPO_ROOT / ".github/workflows/release.yml").read_text()
    sensor = (REPO_ROOT / ".github/workflows/release-sensor.yml").read_text()

    home_draft = home.index("- name: Create draft release")
    home_attest = home.index("- name: Attest release assets")
    home_publish = home.index("- name: Publish immutable release last")
    assert home_draft < home_attest < home_publish
    assert home.rfind("- name:") == home_publish
    assert "release-assets/release-metadata.json" in home
    assert "release-assets/squirrelops-home.rb" in home
    assert "release-assets/RELEASE-VERIFICATION.md" in home
    assert "squirrelops-sensor-*.oci.tar" not in home
    assert "oras " not in home

    sensor_draft = sensor.index("- name: Create draft sensor release")
    sensor_attest = sensor.index("- name: Attest sensor release assets")
    sensor_publish = sensor.index("- name: Promote exact image and publish release last")
    assert sensor_draft < sensor_attest < sensor_publish
    assert sensor.rfind("- name:") == sensor_publish
    final_step = sensor[sensor_publish:]
    assert final_step.index("oras cp") < final_step.index("gh release edit")
    assert "bash scripts/verify-github-release.sh" in final_step
    assert '--source-digest "$RELEASE_COMMIT"' in final_step
    assert '--signer-digest "$RELEASE_COMMIT"' in final_step
    assert "release-assets/sensor-release-metadata.json" in sensor
    assert "release-assets/squirrelops-sensor-*.oci.tar" in sensor
    assert "release-assets/SENSOR-RELEASE-VERIFICATION.md" in sensor
    assert "--from-oci-layout" in sensor
    assert ') == ["amd64", "arm64"]' in sensor
    assert "oras manifest delete" in sensor
    assert '[ "$(oras resolve "${IMAGE}:${SENSOR_VERSION}")" = "$DOCKER_DIGEST" ]' in (sensor)

    for workflow in (home, sensor):
        assert "actions/attest@" in workflow
        assert "attestations: write" in workflow
        assert "id-token: write" in workflow
        assert "artifact-metadata: write" in workflow
        assert "release-assets/SHA256SUMS" in workflow
        assert workflow.count("bash scripts/verify-github-release.sh") >= 3
        assert "gh release verify" in workflow
        assert "--clobber" not in workflow
        assert "push: true" not in workflow
        assert "push-to-registry: true" not in workflow
        assert "gh release delete" not in workflow
        assert "--cleanup-tag" not in workflow


def test_release_policy_token_is_short_lived_narrow_and_environment_gated() -> None:
    home = (REPO_ROOT / ".github/workflows/release.yml").read_text()
    sensor = (REPO_ROOT / ".github/workflows/release-sensor.yml").read_text()

    assert home.count("environment: release") == 3
    assert sensor.count("environment: release") == 2
    for workflow in (home, sensor):
        assert workflow.count("actions/create-github-app-token@") == 2
        assert workflow.count("          permission-actions: read") == 2
        assert workflow.count("          permission-administration: read") == 2
        assert "permission-administration: write" not in workflow
        assert workflow.count("          permission-contents: read") == 2
        assert "RELEASE_POLICY_APP_CLIENT_ID" in workflow
        assert "RELEASE_POLICY_APP_PRIVATE_KEY" in workflow
        assert "RELEASE_POLICY_TOKEN" in workflow
        assert 'GH_TOKEN="$RELEASE_POLICY_TOKEN"' in workflow
        assert "personal access token" not in workflow.lower()


def test_release_verifier_checks_exact_identity_state_and_asset_bytes() -> None:
    verifier = (REPO_ROOT / "scripts/verify-github-release.sh").read_text(encoding="utf-8")

    assert "--json assets,isDraft,isImmutable,tagName,targetCommitish" in verifier
    assert ".tagName == $tag" in verifier
    assert ".targetCommitish == $commit" not in verifier
    assert "git/ref/tags/${RELEASE_TAG}" in verifier
    assert "git/tags/${TAG_OBJECT_SHA}" in verifier
    assert ".object.sha == $commit" in verifier
    assert ".verification.verified == true" in verifier
    assert ".isDraft == false and .isImmutable == true" in verifier
    assert "GitHub digest mismatch" in verifier
    assert "select(length == 1)" in verifier


def test_release_verifier_uses_tag_object_not_target_commitish(
    tmp_path: Path,
) -> None:
    verifier = REPO_ROOT / "scripts/verify-github-release.sh"
    release_tag = "home-v1.2.3"
    commit = "c" * 40
    tag_object = "a" * 40
    asset_dir = tmp_path / "assets"
    asset_dir.mkdir()
    asset = asset_dir / "asset.bin"
    asset.write_bytes(b"reviewed release bytes")
    digest = hashlib.sha256(asset.read_bytes()).hexdigest()

    release_json = tmp_path / "release.json"
    release_json.write_text(
        json.dumps(
            {
                "tagName": release_tag,
                "targetCommitish": "main",
                "isDraft": False,
                "isImmutable": True,
                "assets": [
                    {
                        "name": "asset.bin",
                        "digest": f"sha256:{digest}",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    tag_ref_json = tmp_path / "tag-ref.json"
    tag_ref_json.write_text(
        json.dumps({"object": {"type": "tag", "sha": tag_object}}),
        encoding="utf-8",
    )
    tag_object_json = tmp_path / "tag-object.json"
    tag_object_json.write_text(
        json.dumps(
            {
                "object": {"type": "commit", "sha": commit},
                "verification": {"verified": True, "reason": "valid"},
            }
        ),
        encoding="utf-8",
    )

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_gh = fake_bin / "gh"
    fake_gh.write_text(
        """#!/bin/bash
set -eu
case "$*" in
  "release view"*) cat "$FAKE_RELEASE_JSON" ;;
  *git/ref/tags/*) cat "$FAKE_TAG_REF_JSON" ;;
  *git/tags/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa*) \
    cat "$FAKE_TAG_OBJECT_JSON" ;;
  *) exit 64 ;;
esac
""",
        encoding="utf-8",
    )
    fake_gh.chmod(0o755)
    env = os.environ | {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "FAKE_RELEASE_JSON": str(release_json),
        "FAKE_TAG_REF_JSON": str(tag_ref_json),
        "FAKE_TAG_OBJECT_JSON": str(tag_object_json),
    }
    command = [
        "bash",
        str(verifier),
        "rocketweb/squirrelops-home",
        release_tag,
        commit,
        str(asset_dir),
        "immutable",
    ]

    exact = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert exact.returncode == 0, exact.stderr

    release_payload = json.loads(release_json.read_text(encoding="utf-8"))
    for component_tag in ("app-v1.2.3", "sensor-v1.2.3"):
        release_payload["tagName"] = component_tag
        release_json.write_text(
            json.dumps(release_payload),
            encoding="utf-8",
        )
        component_command = list(command)
        component_command[3] = component_tag
        component = subprocess.run(
            component_command,
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        assert component.returncode == 0, component.stderr

    release_payload["tagName"] = release_tag
    release_json.write_text(
        json.dumps(release_payload),
        encoding="utf-8",
    )

    tag_object_json.write_text(
        json.dumps(
            {
                "object": {"type": "commit", "sha": "d" * 40},
                "verification": {"verified": True, "reason": "valid"},
            }
        ),
        encoding="utf-8",
    )
    moved = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert moved.returncode != 0
    assert "does not resolve to the reviewed commit" in moved.stderr


def test_release_verifier_rejects_legacy_and_malformed_tags(
    tmp_path: Path,
) -> None:
    verifier = REPO_ROOT / "scripts/verify-github-release.sh"
    commit = "c" * 40
    asset_dir = tmp_path / "assets"
    asset_dir.mkdir()

    for release_tag in (
        "v1.2.3",
        "home-v1.2",
        "distribution-v1.2.3",
        "home-v1.2.3-rc1",
    ):
        result = subprocess.run(
            [
                "bash",
                str(verifier),
                "rocketweb/squirrelops-home",
                release_tag,
                commit,
                str(asset_dir),
                "draft",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert "Release tag must be home-vX.Y.Z" in result.stderr


def test_release_docs_require_remote_trust_controls_and_reviewed_promotion() -> None:
    policy = (REPO_ROOT / "docs/RELEASE_SECURITY.md").read_text()

    assert "release immutability" in policy.lower()
    assert "prevent self-review" in policy.lower()
    assert "required reviewer" in policy.lower()
    assert "tag ruleset" in policy.lower()
    assert ".github/release-policy.json" in policy
    assert "bypass actor" in policy.lower()
    assert "git verify-tag" in policy
    assert "hardware" in policy.lower()
    assert "Homebrew" in policy
    assert "squirrelops-home.rb" in policy
    assert 'git tag -s "app-v${APP_VERSION}"' in policy
    assert 'git tag -s "sensor-v${SENSOR_VERSION}"' in policy
    assert 'git tag -s "home-v${DISTRIBUTION_VERSION}"' in policy
    assert "git push --atomic origin" in policy
    assert "git tag -s vX.Y.Z" not in policy
    assert "## Post-release website manifest" in policy
    assert "Do not update `site/public/manifest.json` to a future version" in policy
    assert "Do not advertise a Linux image or sensor release" in policy
    assert "separately reviewed post-release" in policy
    assert "homebrew-cask" in policy
    assert "pull request" in policy.lower()
    assert "release-metadata.json" in policy
    assert "RELEASE-VERIFICATION.md" in policy
    assert "canonical" in policy.lower()
    assert "`Administration: read`" in policy
    assert "write is forbidden" in policy
    assert "`15368`" in policy


def test_required_supply_chain_ci_always_runs_and_validates_controls() -> None:
    workflow = (REPO_ROOT / ".github/workflows/supply-chain-ci.yml").read_text(encoding="utf-8")

    assert "pull_request: {}" in workflow
    assert "branches:" in workflow
    assert "- main" in workflow
    assert "name: Verify release and package controls" in workflow
    assert "name: Verify macOS package lifecycle controls" in workflow
    assert "runs-on: macos-15" in workflow
    assert "paths:" not in workflow
    assert "uv lock --check" in workflow
    assert "test_supply_chain_security.py" in workflow
    assert "test_package_security.py" in workflow
    assert "test_pkg_network_lifecycle.py" in workflow
    assert "Run macOS package lifecycle security tests" in workflow
    assert "bash -n" in workflow
    assert "json.tool .github/release-policy.json" in workflow
    assert ("actions/dependency-review-action@a1d282b36b6f3519aa1f3fc636f609c47dddb294") in workflow
    assert "if: github.event_name == 'pull_request'" in workflow
    assert "fail-on-severity: moderate" in workflow
    assert "fail-on-scopes: runtime, development" in workflow


def test_dependabot_tracks_pinned_action_updates() -> None:
    config = (REPO_ROOT / ".github/dependabot.yml").read_text(encoding="utf-8")

    assert "package-ecosystem: github-actions" in config
    assert "package-ecosystem: docker" in config
    assert "package-ecosystem: uv" in config
    assert "directory: /sensor" in config
    assert "directory: /" in config
    assert "interval: weekly" in config
