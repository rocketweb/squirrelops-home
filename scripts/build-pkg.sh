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
#   SQUIRRELOPS_VERSION   Override version (default: read from VERSION file)
#   BUILD_ARCH            Architecture: "arm64", "x86_64", or "universal"
#                         (default: current arch — set "universal" in CI)
#   SIGNING_IDENTITY      App signing identity (default: "Developer ID Application")
#   INSTALLER_IDENTITY    Installer signing identity (default: "Developer ID Installer")
#   APPLE_ID              Apple ID for notarization (optional)
#   APPLE_TEAM_ID         Apple Team ID for notarization (optional)
#   APPLE_APP_PASSWORD    App-specific password for notarization (optional)
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
# Configuration
# ---------------------------------------------------------------------------
VERSION="${SQUIRRELOPS_VERSION:-$(cat "$REPO_ROOT/VERSION")}"
BUILD_ARCH="${BUILD_ARCH:-$(uname -m)}"
SIGNING_IDENTITY="${SIGNING_IDENTITY:-Developer ID Application}"
INSTALLER_IDENTITY="${INSTALLER_IDENTITY:-Developer ID Installer}"

BUILD_DIR="$REPO_ROOT/build/pkg"
APP_ROOT="$BUILD_DIR/app-root"
SENSOR_ROOT="$BUILD_DIR/sensor-root"
COMPONENTS_DIR="$BUILD_DIR/components"
OUTPUT_DIR="$BUILD_DIR/output"

PKG_NAME="SquirrelOpsHome-${VERSION}.pkg"

echo ""
echo -e "${BOLD}SquirrelOps Home — .pkg Builder${NC}"
echo -e "  Version:  $VERSION"
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

info "App built: $APP_BUNDLE"

# ===========================================================================
# Step 2: Sign the app
# ===========================================================================
step "Step 2: Sign App"

info "Running code signing script..."
bash "$SCRIPT_DIR/sign-app.sh" "$APP_BUNDLE" "$SIGNING_IDENTITY"

# ===========================================================================
# Step 3: Build sensor venv
# ===========================================================================
step "Step 3: Build Sensor Venv"

SENSOR_BUILD_DIR="$BUILD_DIR/sensor-build"
info "Building sensor venv..."
bash "$SCRIPT_DIR/build-sensor-venv.sh" "$SENSOR_BUILD_DIR"

# ===========================================================================
# Step 3b: Sign sensor venv native binaries
# ===========================================================================
step "Step 3b: Sign Sensor Venv Binaries"

if security find-identity -v -p codesigning 2>/dev/null | grep -q "$SIGNING_IDENTITY"; then
    # Find all Mach-O binaries: .so, .dylib, and the Python interpreter
    MACHO_FILES=()
    while IFS= read -r -d '' f; do
        MACHO_FILES+=("$f")
    done < <(find "$SENSOR_BUILD_DIR/venv" -type f \( -name "*.so" -o -name "*.dylib" \) -print0)

    # Also sign the Python interpreter itself
    VENV_PYTHON="$SENSOR_BUILD_DIR/venv/bin/python3"
    if [ -f "$VENV_PYTHON" ] && ! [ -L "$VENV_PYTHON" ]; then
        MACHO_FILES+=("$VENV_PYTHON")
    else
        # Follow symlinks to find the real binary
        REAL_PYTHON="$(readlink -f "$VENV_PYTHON" 2>/dev/null || python3 -c "import os; print(os.path.realpath('$VENV_PYTHON'))")"
        if [ -f "$REAL_PYTHON" ]; then
            MACHO_FILES+=("$REAL_PYTHON")
        fi
    fi

    info "Found ${#MACHO_FILES[@]} Mach-O binaries to sign in sensor venv."

    SIGN_FAIL=0
    for macho in "${MACHO_FILES[@]}"; do
        if codesign --force \
            --options runtime \
            --sign "$SIGNING_IDENTITY" \
            --timestamp \
            "$macho" 2>/dev/null; then
            :
        else
            warn "Failed to sign: $(basename "$macho")"
            SIGN_FAIL=$((SIGN_FAIL + 1))
        fi
    done

    if [ "$SIGN_FAIL" -eq 0 ]; then
        info "All sensor venv binaries signed successfully."
    else
        warn "$SIGN_FAIL binaries failed to sign (notarization may fail)."
    fi
else
    warn "Signing identity '$SIGNING_IDENTITY' not found."
    warn "Skipping sensor venv binary signing."
fi

# ===========================================================================
# Step 4: Assemble payload roots
# ===========================================================================
step "Step 4: Assemble Payload"

# App payload: goes to /Applications
info "Assembling app payload..."
mkdir -p "$APP_ROOT/Applications"
cp -R "$APP_BUNDLE" "$APP_ROOT/Applications/SquirrelOps Home.app"

# Fix SPM resource bundle lookup: the generated Bundle.module accessor looks for
# the resource bundle at Bundle.main.bundleURL (the .app root), but swift build
# places it in Contents/Resources/. Copy it to the .app root so the accessor
# finds it when installed to /Applications.
RESOURCE_BUNDLE="$APP_ROOT/Applications/SquirrelOps Home.app/Contents/Resources/SquirrelOpsHome_SquirrelOpsHome.bundle"
if [ -d "$RESOURCE_BUNDLE" ]; then
    info "Copying resource bundle to .app root for Bundle.module lookup..."
    cp -R "$RESOURCE_BUNDLE" "$APP_ROOT/Applications/SquirrelOps Home.app/SquirrelOpsHome_SquirrelOpsHome.bundle"
fi

# Sensor payload: goes to /Library/SquirrelOps/sensor
SENSOR_INSTALL="$SENSOR_ROOT/Library/SquirrelOps/sensor"
mkdir -p "$SENSOR_INSTALL"

info "Copying sensor venv..."
cp -R "$SENSOR_BUILD_DIR/venv" "$SENSOR_INSTALL/venv"

info "Copying launchd plist template..."
cp "$SENSOR_BUILD_DIR/com.squirrelops.sensor.plist" "$SENSOR_INSTALL/"

info "Copying uninstall script..."
cp "$SCRIPT_DIR/pkg/uninstall.sh" "$SENSOR_INSTALL/uninstall.sh"
chmod +x "$SENSOR_INSTALL/uninstall.sh"

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
    --version "$VERSION" \
    --scripts "$SCRIPT_DIR/pkg/app-scripts" \
    --component-plist "$APP_COMPONENT_PLIST" \
    "$COMPONENTS_DIR/app.pkg"

# Build sensor.pkg (with pre/post install scripts)
info "Building sensor.pkg..."
pkgbuild \
    --root "$SENSOR_ROOT" \
    --install-location / \
    --identifier com.squirrelops.home.sensor \
    --version "$VERSION" \
    --scripts "$SCRIPT_DIR/pkg" \
    "$COMPONENTS_DIR/sensor.pkg"

# ===========================================================================
# Step 6: Build product archive
# ===========================================================================
step "Step 6: Build Product Archive"

# Generate distribution.xml with version and size placeholders filled
DIST_XML="$BUILD_DIR/distribution.xml"
sed \
    -e "s|__VERSION__|${VERSION}|g" \
    -e "s|__APP_SIZE__|${APP_SIZE}|g" \
    -e "s|__SENSOR_SIZE__|${SENSOR_SIZE}|g" \
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

if security find-identity -v -p basic 2>/dev/null | grep -q "$INSTALLER_IDENTITY"; then
    info "Signing .pkg with '$INSTALLER_IDENTITY'..."
    UNSIGNED_PKG="$OUTPUT_DIR/$PKG_NAME"
    SIGNED_PKG="$OUTPUT_DIR/${PKG_NAME%.pkg}-signed.pkg"

    productsign \
        --sign "$INSTALLER_IDENTITY" \
        "$UNSIGNED_PKG" \
        "$SIGNED_PKG"

    # Replace unsigned with signed
    mv "$SIGNED_PKG" "$UNSIGNED_PKG"
    info "Installer package signed."
else
    warn "Installer signing identity '$INSTALLER_IDENTITY' not found."
    warn "Skipping .pkg signing (expected for local dev builds)."
fi

# ===========================================================================
# Step 8: Notarize (if credentials are provided)
# ===========================================================================
step "Step 8: Notarize"

if [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ] && [ -n "${APPLE_APP_PASSWORD:-}" ]; then
    info "Submitting for notarization (15 minute timeout)..."
    NOTARY_OUTPUT="/tmp/notarytool-output.txt"
    xcrun notarytool submit \
        "$OUTPUT_DIR/$PKG_NAME" \
        --apple-id "$APPLE_ID" \
        --team-id "$APPLE_TEAM_ID" \
        --password "$APPLE_APP_PASSWORD" \
        --wait --timeout 15m 2>&1 | tee "$NOTARY_OUTPUT" || true

    # Check if notarization was accepted
    if grep -q "status: Accepted" "$NOTARY_OUTPUT"; then
        info "Notarization accepted. Stapling ticket..."
        xcrun stapler staple "$OUTPUT_DIR/$PKG_NAME"
        info "Notarization complete."
    else
        warn "Notarization was not accepted (likely 'Invalid')."
        warn "The .pkg is signed but not notarized."
        warn "Users may need to right-click → Open on first launch."
        # Try to extract submission ID and fetch log for debugging
        SUBMISSION_ID=$(grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "$NOTARY_OUTPUT" | head -1)
        if [ -n "$SUBMISSION_ID" ]; then
            warn "Fetching notarization log for submission $SUBMISSION_ID..."
            xcrun notarytool log "$SUBMISSION_ID" \
                --apple-id "$APPLE_ID" \
                --team-id "$APPLE_TEAM_ID" \
                --password "$APPLE_APP_PASSWORD" 2>&1 || true
        fi
    fi
else
    warn "Notarization credentials not set (APPLE_ID, APPLE_TEAM_ID, APPLE_APP_PASSWORD)."
    warn "Skipping notarization."
fi

# ===========================================================================
# Step 9: Generate checksum
# ===========================================================================
step "Step 9: Checksum"

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
echo "  Version:    $VERSION"
echo "  Arch:       $BUILD_ARCH"
echo "  Output:     $OUTPUT_DIR/$PKG_NAME"
echo "  Checksum:   $CHECKSUM_FILE"
PKG_SIZE=$(du -sh "$OUTPUT_DIR/$PKG_NAME" | cut -f1)
echo "  Size:       $PKG_SIZE"
echo ""

# ===========================================================================
# Cleanup: Remove build staging directories
# ===========================================================================
# The app-root and sensor-root contain .app bundles with the same bundle ID
# as the installed app. If left on disk, macOS Installer will find them via
# Spotlight and relocate future installs there instead of /Applications.
info "Cleaning up staging directories..."
rm -rf "$APP_ROOT" "$SENSOR_ROOT" "$COMPONENTS_DIR" 2>/dev/null || true
