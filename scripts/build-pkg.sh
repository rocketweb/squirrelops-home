#!/usr/bin/env bash
#
# build-pkg.sh — Build the SquirrelOps Home .pkg installer
#
# Orchestrates the full build pipeline: app build, code signing, sensor venv,
# component packages, product archive, signing, and optional notarization.
#
# Usage:
#   bash scripts/build-pkg.sh
#
# Environment variables:
#   SQUIRRELOPS_DISTRIBUTION_VERSION
#                         Optional assertion; must match the VERSION file
#   SQUIRRELOPS_APP_VERSION
#                         Optional assertion; must match APP_VERSION
#   SQUIRRELOPS_SENSOR_VERSION
#                         Optional assertion; must match sensor/pyproject.toml
#   BUILD_ARCH            Architecture: "arm64" or "x86_64"
#                         (default: current architecture)
#   SIGNING_IDENTITY      App signing identity (default: "Developer ID Application")
#   INSTALLER_IDENTITY    Installer signing identity (default: "Developer ID Installer")
#   APPLE_ID              Apple ID for notarization (optional)
#   APPLE_TEAM_ID         Apple Team ID for notarization (optional)
#   APPLE_APP_PASSWORD    App-specific password for notarization (optional)
#   SKIP_PKG_SIGNING      Set to "1" to skip installer signing for local builds
#   PRODUCTSIGN_TIMESTAMP Set to "none" to disable trusted timestamping
#   SQUIRRELOPS_RELEASE_BUILD
#                         Set to "1" in release automation to require signing,
#                         notarization, stapling, and Gatekeeper acceptance
#   SQUIRRELOPS_LOCAL_TEST_BUILD
#                         Set to "1" for an explicitly ad-hoc-signed package
#                         that can be installed only for local testing
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

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
error() { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }
step()  { echo ""; echo -e "${BOLD}=== $* ===${NC}"; }

# ---------------------------------------------------------------------------
# Configuration and release invariants
# ---------------------------------------------------------------------------
DISTRIBUTION_VERSION="$(tr -d '[:space:]' < "$REPO_ROOT/VERSION")"
APP_VERSION="$(tr -d '[:space:]' < "$REPO_ROOT/APP_VERSION")"
SENSOR_VERSION=$(
    /usr/bin/awk -F'"' '/^version = "[0-9]+\.[0-9]+\.[0-9]+"$/ { print $2; exit }' \
        "$REPO_ROOT/sensor/pyproject.toml"
)
SENSOR_API_PROTOCOL=$(
    /usr/bin/awk '/^SENSOR_API_PROTOCOL_VERSION = [0-9]+$/ { print $3; exit }' \
        "$REPO_ROOT/sensor/src/squirrelops_home_sensor/compatibility.py"
)
APP_SENSOR_API_PROTOCOL=$(
    /usr/bin/awk '/static let current = [0-9]+/ { print $5; exit }' \
        "$REPO_ROOT/app/Sources/SquirrelOpsHome/Connection/SensorAPICompatibility.swift"
)
BUILD_ARCH="${BUILD_ARCH:-$(uname -m)}"
SIGNING_IDENTITY="${SIGNING_IDENTITY:-Developer ID Application}"
INSTALLER_IDENTITY="${INSTALLER_IDENTITY:-Developer ID Installer}"
SKIP_PKG_SIGNING="${SKIP_PKG_SIGNING:-0}"
PRODUCTSIGN_TIMESTAMP="${PRODUCTSIGN_TIMESTAMP:-}"
RELEASE_BUILD="${SQUIRRELOPS_RELEASE_BUILD:-0}"
LOCAL_TEST_BUILD="${SQUIRRELOPS_LOCAL_TEST_BUILD:-0}"

case "$RELEASE_BUILD" in
    0|1) ;;
    *) error "SQUIRRELOPS_RELEASE_BUILD must be 0 or 1." ;;
esac
case "$LOCAL_TEST_BUILD" in
    0|1) ;;
    *) error "SQUIRRELOPS_LOCAL_TEST_BUILD must be 0 or 1." ;;
esac

if [ "$LOCAL_TEST_BUILD" = "1" ]; then
    if [ "$RELEASE_BUILD" = "1" ]; then
        error "A release build cannot be a local test build."
    fi
    if [ "$SIGNING_IDENTITY" != "Developer ID Application" ] \
        && [ "$SIGNING_IDENTITY" != "-" ]; then
        error "A local test build cannot use a real signing identity: $SIGNING_IDENTITY"
    fi
    SIGNING_IDENTITY="-"
fi

if [ "$RELEASE_BUILD" = "1" ]; then
    if [ "$SKIP_PKG_SIGNING" = "1" ]; then
        error "Release builds cannot set SKIP_PKG_SIGNING=1."
    fi
    if [ "$PRODUCTSIGN_TIMESTAMP" = "none" ]; then
        error "Release builds require trusted timestamping."
    fi
    if [ -z "${APPLE_ID:-}" ] \
        || [ -z "${APPLE_TEAM_ID:-}" ] \
        || [ -z "${APPLE_APP_PASSWORD:-}" ]; then
        error "Release builds require notarization credentials (APPLE_ID, APPLE_TEAM_ID, and APPLE_APP_PASSWORD)."
    fi
fi

if [[ ! "$DISTRIBUTION_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    error "VERSION must contain a semantic version (for example, 1.2.3)."
fi
if [[ ! "$APP_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    error "APP_VERSION must contain a semantic version (for example, 1.2.3)."
fi
if [[ ! "$SENSOR_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    error "sensor/pyproject.toml must contain a semantic version."
fi
if [[ ! "$SENSOR_API_PROTOCOL" =~ ^[1-9][0-9]*$ ]] \
    || [ "$APP_SENSOR_API_PROTOCOL" != "$SENSOR_API_PROTOCOL" ]; then
    error "App and sensor API protocol contracts do not match."
fi
if [ -n "${SQUIRRELOPS_DISTRIBUTION_VERSION:-}" ] \
    && [ "$SQUIRRELOPS_DISTRIBUTION_VERSION" != "$DISTRIBUTION_VERSION" ]; then
    error "SQUIRRELOPS_DISTRIBUTION_VERSION does not match authoritative VERSION ($DISTRIBUTION_VERSION)."
fi
if [ -n "${SQUIRRELOPS_APP_VERSION:-}" ] \
    && [ "$SQUIRRELOPS_APP_VERSION" != "$APP_VERSION" ]; then
    error "SQUIRRELOPS_APP_VERSION does not match authoritative APP_VERSION ($APP_VERSION)."
fi
if [ -n "${SQUIRRELOPS_SENSOR_VERSION:-}" ] \
    && [ "$SQUIRRELOPS_SENSOR_VERSION" != "$SENSOR_VERSION" ]; then
    error "SQUIRRELOPS_SENSOR_VERSION does not match sensor/pyproject.toml ($SENSOR_VERSION)."
fi

INSTALL_SCRIPT_VERSION=$(
    /usr/bin/awk -F'"' '/^SQUIRRELOPS_SENSOR_VERSION="[0-9]+\.[0-9]+\.[0-9]+"$/ { print $2; exit }' \
        "$REPO_ROOT/scripts/install.sh"
)
if [ "$INSTALL_SCRIPT_VERSION" != "$SENSOR_VERSION" ]; then
    error "scripts/install.sh sensor version ($INSTALL_SCRIPT_VERSION) does not match sensor/pyproject.toml ($SENSOR_VERSION)."
fi

case "$BUILD_ARCH" in
    arm64|x86_64) ;;
    universal)
        error "Universal packages are unsupported because the embedded Python runtime is architecture-specific. Build one package per architecture."
        ;;
    *)
        error "Unsupported package architecture: $BUILD_ARCH"
        ;;
esac

validate_macho_arch() {
    local binary="$1"
    local expected_arch="$2"
    local actual_arches
    if [ ! -x "$binary" ]; then
        error "Required executable is missing or unusable: $binary"
    fi
    if ! actual_arches=$(/usr/bin/lipo -archs "$binary" 2>/dev/null); then
        error "Could not inspect Mach-O architectures for $binary"
    fi
    case " $actual_arches " in
        *" $expected_arch "*) ;;
        *)
            error "$binary does not contain required architecture $expected_arch (found: $actual_arches)."
            ;;
    esac
}

BUILD_DIR="$REPO_ROOT/build/pkg"
APP_ROOT="$BUILD_DIR/app-root"
SENSOR_ROOT="$BUILD_DIR/sensor-root"
COMPONENTS_DIR="$BUILD_DIR/components"
OUTPUT_DIR="$BUILD_DIR/output"

PKG_NAME="SquirrelOpsHome-${DISTRIBUTION_VERSION}.pkg"

echo ""
echo -e "${BOLD}SquirrelOps Home — .pkg Builder${NC}"
echo -e "  Distribution: $DISTRIBUTION_VERSION"
echo -e "  App:          $APP_VERSION"
echo -e "  Sensor:       $SENSOR_VERSION"
echo -e "  Arch:     $BUILD_ARCH"
echo ""

# ---------------------------------------------------------------------------
# Clean previous build
# ---------------------------------------------------------------------------
info "Cleaning previous build artifacts..."
rm -rf "$BUILD_DIR"
mkdir -p "$APP_ROOT" "$SENSOR_ROOT" "$COMPONENTS_DIR" "$OUTPUT_DIR"

# ===========================================================================
# Step 1: Build the app
# ===========================================================================
step "Step 1: Build App"

info "Building SquirrelOps Home.app (config=release, arch=$BUILD_ARCH)..."
(
    cd "$REPO_ROOT/app"
    BUILD_CONFIG=release BUILD_ARCH="$BUILD_ARCH" bash build-app.sh
)

# Locate the built .app bundle
if [ "$BUILD_ARCH" = "universal" ]; then
    APP_BUILD_DIR="$REPO_ROOT/app/.build/apple/Products/Release"
else
    APP_BUILD_DIR="$REPO_ROOT/app/.build/${BUILD_ARCH}-apple-macosx/release"
fi

APP_BUNDLE="$APP_BUILD_DIR/SquirrelOpsHome.app"

if [ ! -d "$APP_BUNDLE" ]; then
    error "App bundle not found at $APP_BUNDLE"
fi

APP_EXECUTABLE="$APP_BUNDLE/Contents/MacOS/SquirrelOpsHome"
HELPER_PATH="$APP_BUNDLE/Contents/Library/LaunchServices/com.squirrelops.helper"
validate_macho_arch "$APP_EXECUTABLE" "$BUILD_ARCH"
validate_macho_arch "$HELPER_PATH" "$BUILD_ARCH"

info "App built: $APP_BUNDLE"

if [ "$LOCAL_TEST_BUILD" = "1" ]; then
    info "Marking app bundle as an explicit local test build..."
    /usr/bin/touch \
        "$APP_BUNDLE/Contents/Resources/com.squirrelops.local-test-build"
fi

# ===========================================================================
# Step 2: Sign the app
# ===========================================================================
step "Step 2: Sign App"

info "Running code signing script..."
bash "$SCRIPT_DIR/sign-app.sh" "$APP_BUNDLE" "$SIGNING_IDENTITY"
if [ "$RELEASE_BUILD" = "1" ]; then
    codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE"
    info "Release app signature verified."
fi

# ===========================================================================
# Step 3: Build standalone sensor runtime
# ===========================================================================
step "Step 3: Build Standalone Sensor Runtime"

SENSOR_BUILD_DIR="$BUILD_DIR/sensor-build"
info "Building pinned standalone sensor runtime..."
PYTHON_BUILD_MODE=standalone bash "$SCRIPT_DIR/build-sensor-venv.sh" "$SENSOR_BUILD_DIR"

# ===========================================================================
# Step 3b: Sign sensor Python native binaries
# ===========================================================================
step "Step 3b: Sign Sensor Python Binaries"

# A distributable package must never inherit the build host's Python runtime.
SENSOR_PYTHON_MODE=$(cat "$SENSOR_BUILD_DIR/.python-mode" 2>/dev/null || true)
if [ "$SENSOR_PYTHON_MODE" != "standalone" ]; then
    error "Sensor package builder did not produce the required standalone Python runtime."
fi
info "Sensor Python mode: $SENSOR_PYTHON_MODE"

SENSOR_PYTHON_DIR="$SENSOR_BUILD_DIR/python"
SENSOR_PYTHON_BIN="$SENSOR_PYTHON_DIR/bin/python3"
SENSOR_REQUIREMENTS_LOCK="$SENSOR_BUILD_DIR/requirements.lock"
SENSOR_BUILD_REQUIREMENTS_LOCK="$SENSOR_BUILD_DIR/build-requirements.lock"
validate_macho_arch "$SENSOR_PYTHON_BIN" "$BUILD_ARCH"
if [ ! -s "$SENSOR_REQUIREMENTS_LOCK" ]; then
    error "Sensor package builder did not produce requirements.lock."
fi
if [ ! -s "$SENSOR_BUILD_REQUIREMENTS_LOCK" ]; then
    error "Sensor package builder did not produce build-requirements.lock."
fi

BUILT_SENSOR_VERSION=$(
    PYTHONDONTWRITEBYTECODE=1 "$SENSOR_PYTHON_BIN" -c \
        'from importlib.metadata import version; print(version("squirrelops-home-sensor"))'
)
if [ "$BUILT_SENSOR_VERSION" != "$SENSOR_VERSION" ]; then
    error "Embedded sensor reports $BUILT_SENSOR_VERSION, expected $SENSOR_VERSION."
fi

if { [ "$LOCAL_TEST_BUILD" = "1" ] && [ "$SIGNING_IDENTITY" = "-" ]; } \
    || security find-identity -v -p codesigning 2>/dev/null \
        | grep -Fq -- "$SIGNING_IDENTITY"; then
    # Find all Mach-O binaries: .so, .dylib, and the Python interpreter
    MACHO_FILES=()
    while IFS= read -r -d '' f; do
        MACHO_FILES+=("$f")
    done < <(find "$SENSOR_PYTHON_DIR" -type f \( -name "*.so" -o -name "*.dylib" \) -print0)

    # Also sign the Python interpreter itself, but only when it is embedded in
    # the package payload. Venv builds usually point at a Homebrew/system
    # interpreter via symlink; signing that external binary breaks the local
    # Python/framework signature relationship.
    PYTHON_BIN="$SENSOR_PYTHON_DIR/bin/python3"
    if [ -f "$PYTHON_BIN" ] && ! [ -L "$PYTHON_BIN" ]; then
        MACHO_FILES+=("$PYTHON_BIN")
    elif [ "$SENSOR_PYTHON_MODE" = "standalone" ]; then
        # Follow symlinks to find the real binary
        REAL_PYTHON="$(readlink -f "$PYTHON_BIN" 2>/dev/null || PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" -c "import os,sys; print(os.path.realpath(sys.executable))" 2>/dev/null || true)"
        if [ -n "$REAL_PYTHON" ] && [ -f "$REAL_PYTHON" ] && [[ "$REAL_PYTHON" == "$SENSOR_PYTHON_DIR"* ]]; then
            MACHO_FILES+=("$REAL_PYTHON")
        else
            warn "Embedded Python binary not found inside sensor payload; skipping interpreter signing."
        fi
    else
        warn "Venv Python is an external symlink; skipping interpreter signing."
    fi

    info "Found ${#MACHO_FILES[@]} Mach-O binaries to sign."

    SIGN_FAIL=0
    for macho in "${MACHO_FILES[@]}"; do
        SIGN_NATIVE_ARGS=(codesign --force --sign "$SIGNING_IDENTITY")
        if [ "$SIGNING_IDENTITY" != "-" ]; then
            # Developer ID binaries share a Team ID, so Hardened Runtime
            # library validation accepts the bundled standalone Python dylibs.
            # Ad-hoc signatures have no shared Team ID; enabling runtime here
            # would make the explicit local-test sensor unable to launch.
            SIGN_NATIVE_ARGS+=(--options runtime --timestamp)
        fi
        SIGN_NATIVE_ARGS+=("$macho")
        if "${SIGN_NATIVE_ARGS[@]}" 2>/dev/null \
            && codesign --verify --strict --verbose=2 "$macho" 2>/dev/null; then
            :
        else
            warn "Failed to sign: $(basename "$macho")"
            SIGN_FAIL=$((SIGN_FAIL + 1))
        fi
    done

    if [ "$SIGN_FAIL" -eq 0 ]; then
        info "All sensor Python binaries signed successfully."
    elif [ "$RELEASE_BUILD" = "1" ]; then
        error "Release builds require every sensor Mach-O binary to be signed and verified; $SIGN_FAIL failed."
    else
        warn "$SIGN_FAIL binaries failed to sign (notarization may fail)."
    fi
else
    if [ "$RELEASE_BUILD" = "1" ]; then
        error "Release builds require an available app signing identity: $SIGNING_IDENTITY"
    fi
    warn "Signing identity '$SIGNING_IDENTITY' not found."
    warn "Skipping sensor Python binary signing."
fi

# ===========================================================================
# Step 4: Assemble payload roots
# ===========================================================================
step "Step 4: Assemble Payload"

# App payload: goes to /Applications
info "Assembling app payload..."
mkdir -p "$APP_ROOT/Applications"
STAGED_APP_BUNDLE="$APP_ROOT/Applications/SquirrelOps Home.app"
cp -R "$APP_BUNDLE" "$STAGED_APP_BUNDLE"
if [ "$RELEASE_BUILD" = "1" ]; then
    codesign --verify --deep --strict --verbose=2 "$STAGED_APP_BUNDLE"
fi
if LC_ALL=C /usr/bin/grep -aFRl "$REPO_ROOT" "$APP_ROOT" >/dev/null; then
    error "Staged app payload still contains the build-host repository path."
fi

# Sensor payload: goes to /Library/SquirrelOps/sensor
SENSOR_INSTALL="$SENSOR_ROOT/Library/SquirrelOps/sensor"
mkdir -p "$SENSOR_INSTALL"

info "Copying standalone sensor Python environment..."
cp -R "$SENSOR_BUILD_DIR/python" "$SENSOR_INSTALL/python"

# Write the mode marker into the install payload so postinstall knows which
# Python path to use in the LaunchDaemon plist.
echo "$SENSOR_PYTHON_MODE" > "$SENSOR_INSTALL/.python-mode"
printf '%s\n' "$SENSOR_VERSION" > "$SENSOR_INSTALL/VERSION"
cat > "$SENSOR_INSTALL/release-components.json" <<EOF
{
  "schema_version": 1,
  "distribution_version": "$DISTRIBUTION_VERSION",
  "app_version": "$APP_VERSION",
  "sensor_version": "$SENSOR_VERSION",
  "sensor_api_protocol": $SENSOR_API_PROTOCOL
}
EOF

info "Copying launchd plist template..."
cp "$SENSOR_BUILD_DIR/com.squirrelops.sensor.plist" "$SENSOR_INSTALL/"

info "Copying locked dependency manifest..."
cp "$SENSOR_REQUIREMENTS_LOCK" "$SENSOR_INSTALL/requirements.lock"
cp "$SENSOR_BUILD_REQUIREMENTS_LOCK" \
    "$SENSOR_INSTALL/build-requirements.lock"

info "Copying device signatures..."
mkdir -p "$SENSOR_INSTALL/signatures"
cp "$REPO_ROOT/sensor/signatures/device_signatures.json" "$SENSOR_INSTALL/signatures/"

info "Copying uninstall script..."
cp "$SCRIPT_DIR/pkg/uninstall.sh" "$SENSOR_INSTALL/uninstall.sh"
chmod +x "$SENSOR_INSTALL/uninstall.sh"

info "Validating staged sensor payload contains no build-host paths..."
bash "$SCRIPT_DIR/sanitize-python-runtime.sh" validate \
    "$SENSOR_INSTALL" "$REPO_ROOT" "$BUILD_DIR"

# ===========================================================================
# Step 5: Build component packages
# ===========================================================================
step "Step 5: Build Component Packages"

# Calculate sizes for distribution.xml (in KB)
APP_SIZE=$(du -sk "$APP_ROOT" | cut -f1)
SENSOR_SIZE=$(du -sk "$SENSOR_ROOT" | cut -f1)

info "App size: ${APP_SIZE} KB"
info "Sensor size: ${SENSOR_SIZE} KB"

# Build app.pkg — analyze first to disable bundle relocation, then build.
# Without --component-plist, pkgbuild defaults to relocatable=true inside the
# component PackageInfo, which causes macOS Installer to search the disk for
# existing bundles with the same ID and install there instead of /Applications.
info "Building app.pkg..."
APP_COMPONENT_PLIST="$BUILD_DIR/app-component.plist"
pkgbuild --analyze --root "$APP_ROOT" "$APP_COMPONENT_PLIST"
# Set BundleIsRelocatable to false for every bundle found
/usr/libexec/PlistBuddy -c "Set :0:BundleIsRelocatable false" "$APP_COMPONENT_PLIST"

pkgbuild \
    --root "$APP_ROOT" \
    --install-location / \
    --identifier com.squirrelops.home.app \
    --version "$APP_VERSION" \
    --scripts "$SCRIPT_DIR/pkg/app-scripts" \
    --component-plist "$APP_COMPONENT_PLIST" \
    "$COMPONENTS_DIR/app.pkg"

# Build sensor.pkg (with pre/post install scripts)
info "Building sensor.pkg..."
pkgbuild \
    --root "$SENSOR_ROOT" \
    --install-location / \
    --identifier com.squirrelops.home.sensor \
    --version "$SENSOR_VERSION" \
    --scripts "$SCRIPT_DIR/pkg" \
    "$COMPONENTS_DIR/sensor.pkg"

# ===========================================================================
# Step 6: Build product archive
# ===========================================================================
step "Step 6: Build Product Archive"

# Generate distribution.xml with version and size placeholders filled
DIST_XML="$BUILD_DIR/distribution.xml"
sed \
    -e "s|__DISTRIBUTION_VERSION__|${DISTRIBUTION_VERSION}|g" \
    -e "s|__APP_VERSION__|${APP_VERSION}|g" \
    -e "s|__SENSOR_VERSION__|${SENSOR_VERSION}|g" \
    -e "s|__APP_SIZE__|${APP_SIZE}|g" \
    -e "s|__SENSOR_SIZE__|${SENSOR_SIZE}|g" \
    -e "s|__HOST_ARCH__|${BUILD_ARCH}|g" \
    "$SCRIPT_DIR/pkg/distribution.xml" > "$DIST_XML"

info "Building product archive: $PKG_NAME"
productbuild \
    --distribution "$DIST_XML" \
    --package-path "$COMPONENTS_DIR" \
    "$OUTPUT_DIR/$PKG_NAME"

info "Product archive created: $OUTPUT_DIR/$PKG_NAME"

# ===========================================================================
# Step 7: Sign the .pkg (if identity is available)
# ===========================================================================
step "Step 7: Sign Installer Package"

if [ "$SKIP_PKG_SIGNING" = "1" ]; then
    if [ "$RELEASE_BUILD" = "1" ]; then
        error "Release builds cannot set SKIP_PKG_SIGNING=1."
    fi
    warn "SKIP_PKG_SIGNING=1; skipping .pkg signing."
elif security find-identity -v -p basic 2>/dev/null \
    | grep -Fq -- "$INSTALLER_IDENTITY"; then
    info "Signing .pkg with '$INSTALLER_IDENTITY'..."
    UNSIGNED_PKG="$OUTPUT_DIR/$PKG_NAME"
    SIGNED_PKG="$OUTPUT_DIR/${PKG_NAME%.pkg}-signed.pkg"

    PRODUCTSIGN_ARGS=(productsign)
    if [ -n "$PRODUCTSIGN_TIMESTAMP" ]; then
        PRODUCTSIGN_ARGS+=(--timestamp="$PRODUCTSIGN_TIMESTAMP")
    fi
    PRODUCTSIGN_ARGS+=(
        --sign "$INSTALLER_IDENTITY"
        "$UNSIGNED_PKG"
        "$SIGNED_PKG"
    )

    "${PRODUCTSIGN_ARGS[@]}"

    # Replace unsigned with signed
    mv "$SIGNED_PKG" "$UNSIGNED_PKG"
    pkgutil --check-signature "$UNSIGNED_PKG"
    info "Installer package signed."
else
    if [ "$RELEASE_BUILD" = "1" ]; then
        error "Release builds require an available installer signing identity: $INSTALLER_IDENTITY"
    fi
    warn "Installer signing identity '$INSTALLER_IDENTITY' not found."
    warn "Skipping .pkg signing (expected for local dev builds)."
fi

# ===========================================================================
# Step 8: Notarize (if credentials are provided)
# ===========================================================================
step "Step 8: Notarize"

if [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ] && [ -n "${APPLE_APP_PASSWORD:-}" ]; then
    info "Submitting for notarization (15 minute timeout)..."
    NOTARY_OUTPUT="$(mktemp "${TMPDIR:-/tmp}/squirrelops-notary.XXXXXX")"
    cleanup_notary_output() {
        rm -f "$NOTARY_OUTPUT"
    }
    trap cleanup_notary_output EXIT

    NOTARY_SUBMIT_SUCCEEDED=0
    if xcrun notarytool submit \
            "$OUTPUT_DIR/$PKG_NAME" \
            --apple-id "$APPLE_ID" \
            --team-id "$APPLE_TEAM_ID" \
            --password "$APPLE_APP_PASSWORD" \
            --wait --timeout 15m 2>&1 | tee "$NOTARY_OUTPUT"; then
        NOTARY_SUBMIT_SUCCEEDED=1
    fi

    # Check if notarization was accepted
    if [ "$NOTARY_SUBMIT_SUCCEEDED" = "1" ] \
        && grep -Fq "status: Accepted" "$NOTARY_OUTPUT"; then
        info "Notarization accepted. Stapling ticket..."
        xcrun stapler staple "$OUTPUT_DIR/$PKG_NAME"
        xcrun stapler validate "$OUTPUT_DIR/$PKG_NAME"
        info "Notarization complete."
    else
        warn "Notarization was not accepted (likely 'Invalid')."
        warn "The .pkg is signed but not notarized."
        # Try to extract submission ID and fetch log for debugging
        SUBMISSION_ID=$(grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "$NOTARY_OUTPUT" | head -1 || true)
        if [ -n "$SUBMISSION_ID" ]; then
            warn "Fetching notarization log for submission $SUBMISSION_ID..."
            xcrun notarytool log "$SUBMISSION_ID" \
                --apple-id "$APPLE_ID" \
                --team-id "$APPLE_TEAM_ID" \
                --password "$APPLE_APP_PASSWORD" 2>&1 || true
        fi
        if [ "$RELEASE_BUILD" = "1" ]; then
            error "Release notarization was not accepted; refusing to publish the installer."
        fi
        warn "Local build will continue without notarization."
    fi

    rm -f "$NOTARY_OUTPUT"
    trap - EXIT
else
    if [ "$RELEASE_BUILD" = "1" ]; then
        error "Release builds require notarization credentials (APPLE_ID, APPLE_TEAM_ID, and APPLE_APP_PASSWORD)."
    fi
    warn "Notarization credentials not set (APPLE_ID, APPLE_TEAM_ID, APPLE_APP_PASSWORD)."
    warn "Skipping notarization."
fi

# ===========================================================================
# Step 9: Verify release artifact
# ===========================================================================
step "Step 9: Verify Release Artifact"

if [ "$RELEASE_BUILD" = "1" ]; then
    codesign --verify --deep --strict --verbose=2 "$STAGED_APP_BUNDLE"
    pkgutil --check-signature "$OUTPUT_DIR/$PKG_NAME"
    xcrun stapler validate "$OUTPUT_DIR/$PKG_NAME"
    spctl --assess --type install --verbose=2 "$OUTPUT_DIR/$PKG_NAME"
    info "Release signature, notarization ticket, and Gatekeeper checks passed."
else
    info "Local build mode; strict release verification was not requested."
fi

# ===========================================================================
# Step 10: Generate checksum
# ===========================================================================
step "Step 10: Checksum"

CHECKSUM_FILE="$OUTPUT_DIR/${PKG_NAME}.sha256"
(cd "$OUTPUT_DIR" && shasum -a 256 "$PKG_NAME" > "$CHECKSUM_FILE")
info "SHA256: $(cat "$CHECKSUM_FILE")"

# ===========================================================================
# Summary
# ===========================================================================
echo ""
echo -e "${BOLD}=========================================${NC}"
echo -e "${BOLD}  .pkg Build Complete${NC}"
echo -e "${BOLD}=========================================${NC}"
echo ""
echo "  Distribution: $DISTRIBUTION_VERSION"
echo "  App:          $APP_VERSION"
echo "  Sensor:       $SENSOR_VERSION"
echo "  Arch:         $BUILD_ARCH"
echo "  Output:       $OUTPUT_DIR/$PKG_NAME"
echo "  Checksum:     $CHECKSUM_FILE"
PKG_SIZE=$(du -sh "$OUTPUT_DIR/$PKG_NAME" | cut -f1)
echo "  Size:       $PKG_SIZE"
if [ "$LOCAL_TEST_BUILD" = "1" ]; then
    echo ""
    echo "  Before installing this local test package, create the one-time opt-in:"
    echo "  sudo /usr/bin/install -o root -g wheel -m 600 /dev/null /var/db/com.squirrelops.allow-local-test"
    echo "  The installer consumes the opt-in after a successful helper installation."
fi
echo ""

# ===========================================================================
# Cleanup: Remove build staging directories
# ===========================================================================
# The app-root and sensor-root contain .app bundles with the same bundle ID
# as the installed app. If left on disk, macOS Installer will find them via
# Spotlight and relocate future installs there instead of /Applications.
info "Cleaning up staging directories..."
rm -rf "$APP_ROOT" "$SENSOR_ROOT" "$COMPONENTS_DIR" 2>/dev/null || true
