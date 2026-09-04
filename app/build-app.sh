#!/usr/bin/env bash
#
# Build SquirrelOpsHome.app bundle from Swift Package Manager output.
#
# Usage:
#   cd app && bash build-app.sh
#
# Environment variables:
#   BUILD_CONFIG  - "debug" (default) or "release"
#   BUILD_ARCH    - "arm64", "x86_64", or "universal" (default: current arch)
#   SQUIRRELOPS_APP_VERSION - optional assertion; must match ../APP_VERSION
#   SQUIRRELOPS_GUEST_BUNDLE - architecture-specific Studio Mini guest bundle
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$SCRIPT_DIR"

APP_VERSION="$(tr -d '[:space:]' < "$SCRIPT_DIR/../APP_VERSION")"
DISTRIBUTION_VERSION="$(tr -d '[:space:]' < "$SCRIPT_DIR/../VERSION")"
if [ -n "${SQUIRRELOPS_APP_VERSION:-}" ] \
    && [ "$SQUIRRELOPS_APP_VERSION" != "$APP_VERSION" ]; then
    echo "[x] App version override does not match authoritative APP_VERSION ($APP_VERSION)." >&2
    exit 1
fi

APP_NAME="SquirrelOpsHome"
HELPER_NAME="SquirrelOpsHelper"
DECEPTION_RUNTIME_NAME="SquirrelOpsDeceptionGuest"
BUILD_CONFIG="${BUILD_CONFIG:-debug}"
BUILD_ARCH="${BUILD_ARCH:-$(uname -m)}"
GUEST_BUNDLE="${SQUIRRELOPS_GUEST_BUNDLE:-$REPO_ROOT/guest/studio-mini/build/$BUILD_ARCH}"

fail() {
    echo "[x] $*" >&2
    exit 1
}

strip_release_binary() {
    local binary="$1"

    /usr/bin/strip -S "$binary" \
        || fail "Could not strip release debug metadata from $binary"
}

validate_no_build_host_paths() {
    local binary="$1"

    if LC_ALL=C /usr/bin/grep -aFq "$REPO_ROOT" "$binary"; then
        fail "Release binary still embeds the build-host repository path: $binary"
    fi
}

# --- Construct swift build flags ---

SWIFT_FLAGS=()

if [ "$BUILD_CONFIG" = "release" ]; then
    SWIFT_FLAGS+=(-c release)
fi

if [ "$BUILD_ARCH" = "universal" ]; then
    SWIFT_FLAGS+=(--arch arm64 --arch x86_64)
elif [ "$BUILD_ARCH" != "$(uname -m)" ]; then
    SWIFT_FLAGS+=(--arch "$BUILD_ARCH")
fi

# --- Determine build output directory ---

if [ "$BUILD_ARCH" = "universal" ]; then
    # Universal builds go into .build/apple/Products/{Release,Debug}
    if [ "$BUILD_CONFIG" = "release" ]; then
        BUILD_DIR=".build/apple/Products/Release"
    else
        BUILD_DIR=".build/apple/Products/Debug"
    fi
else
    # Single-arch builds go into .build/{arch}-apple-macosx/{release,debug}
    BUILD_DIR=".build/${BUILD_ARCH}-apple-macosx/${BUILD_CONFIG}"
fi

APP_BUNDLE="$BUILD_DIR/$APP_NAME.app"

echo "[+] Config: $BUILD_CONFIG | Arch: $BUILD_ARCH"
echo "[+] Build dir: $BUILD_DIR"
if [ ${#SWIFT_FLAGS[@]} -gt 0 ]; then
    echo "[+] Building with flags: ${SWIFT_FLAGS[*]}..."
    swift build "${SWIFT_FLAGS[@]}"
else
    echo "[+] Building..."
    swift build
fi

echo "[+] Creating .app bundle..."
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"

# Copy executable
APP_EXECUTABLE="$APP_BUNDLE/Contents/MacOS/$APP_NAME"
cp "$BUILD_DIR/$APP_NAME" "$APP_EXECUTABLE"

# Copy bundled resources (fonts etc.) using glob to handle naming variations
for bundle in "$BUILD_DIR"/*_"${APP_NAME}".bundle; do
    if [ -d "$bundle" ]; then
        cp -R "$bundle" "$APP_BUNDLE/Contents/Resources/"
    fi
done

# The privileged helper is required for ARP scans, decoys, and alerting. An app
# without it is not a functional SquirrelOps Home build.
HELPER_BUNDLE_ID="com.squirrelops.helper"
if [ ! -x "$BUILD_DIR/$HELPER_NAME" ]; then
    echo "[x] Required helper binary is missing or not executable: $BUILD_DIR/$HELPER_NAME" >&2
    exit 1
fi
echo "[+] Bundling helper: $HELPER_NAME -> $HELPER_BUNDLE_ID"
mkdir -p "$APP_BUNDLE/Contents/Library/LaunchServices"
HELPER_PATH="$APP_BUNDLE/Contents/Library/LaunchServices/$HELPER_BUNDLE_ID"
cp "$BUILD_DIR/$HELPER_NAME" "$HELPER_PATH"
chmod 755 "$HELPER_PATH"

# The deep-decoy runtime is a separate unprivileged process. It owns the
# Virtualization.framework VM and opaque TCP-to-Virtio relays, keeping SSH and
# SMB parsers out of the sensor and privileged helper.
DECEPTION_RUNTIME_BUNDLE_ID="com.squirrelops.deception-guest"
if [ ! -x "$BUILD_DIR/$DECEPTION_RUNTIME_NAME" ]; then
    echo "[x] Required deception runtime is missing or not executable: $BUILD_DIR/$DECEPTION_RUNTIME_NAME" >&2
    exit 1
fi
echo "[+] Bundling deception runtime: $DECEPTION_RUNTIME_NAME -> $DECEPTION_RUNTIME_BUNDLE_ID"
mkdir -p "$APP_BUNDLE/Contents/Library/Helpers"
DECEPTION_RUNTIME_PATH="$APP_BUNDLE/Contents/Library/Helpers/$DECEPTION_RUNTIME_BUNDLE_ID"
cp "$BUILD_DIR/$DECEPTION_RUNTIME_NAME" "$DECEPTION_RUNTIME_PATH"
chmod 755 "$DECEPTION_RUNTIME_PATH"
if [ "$BUILD_CONFIG" = "debug" ]; then
    echo "[+] Applying local virtualization entitlement to deception runtime..."
    codesign --force --sign - \
        --identifier "$DECEPTION_RUNTIME_BUNDLE_ID" \
        --entitlements "$REPO_ROOT/app/entitlements/deception-guest.entitlements" \
        "$DECEPTION_RUNTIME_PATH"
fi

# Guest bytes are immutable app resources. The sensor validates them again at
# runtime before invoking Virtualization.framework.
if [ "$BUILD_ARCH" = "universal" ]; then
    if [ "$BUILD_CONFIG" = "release" ]; then
        fail "Universal release apps cannot contain one architecture-specific guest."
    fi
elif [ -d "$GUEST_BUNDLE" ]; then
    python3 "$REPO_ROOT/scripts/verify-guest-bundle.py" \
        "$GUEST_BUNDLE" --architecture "$BUILD_ARCH"
    GUEST_DESTINATION="$APP_BUNDLE/Contents/Resources/DeceptionGuest"
    mkdir -p "$GUEST_DESTINATION"
    cp "$GUEST_BUNDLE/manifest.json" "$GUEST_DESTINATION/manifest.json"
    cp "$GUEST_BUNDLE/vmlinuz" "$GUEST_DESTINATION/vmlinuz"
    cp "$GUEST_BUNDLE/studio-mini.initramfs" \
        "$GUEST_DESTINATION/studio-mini.initramfs"
    chmod 0444 "$GUEST_DESTINATION"/*
    python3 "$REPO_ROOT/scripts/verify-guest-bundle.py" \
        "$GUEST_DESTINATION" --architecture "$BUILD_ARCH"
elif [ "$BUILD_CONFIG" = "release" ]; then
    fail "Required Studio Mini guest bundle is missing: $GUEST_BUNDLE"
else
    echo "[!] Studio Mini guest bundle is absent; the deep decoy will be unavailable." >&2
fi

if [ "$BUILD_CONFIG" = "release" ]; then
    echo "[+] Removing build-host metadata from release binaries..."
    strip_release_binary "$APP_EXECUTABLE"
    strip_release_binary "$HELPER_PATH"
    strip_release_binary "$DECEPTION_RUNTIME_PATH"

    validate_no_build_host_paths "$APP_EXECUTABLE"
    validate_no_build_host_paths "$HELPER_PATH"
    validate_no_build_host_paths "$DECEPTION_RUNTIME_PATH"
fi

# Copy app icon
ICON_SRC="$BUILD_DIR/${APP_NAME}_${APP_NAME}.bundle/AppIcon.icns"
if [ -f "$ICON_SRC" ]; then
    cp "$ICON_SRC" "$APP_BUNDLE/Contents/Resources/AppIcon.icns"
else
    # Fallback: copy from source tree
    cp "Sources/${APP_NAME}/Resources/AppIcon.icns" "$APP_BUNDLE/Contents/Resources/AppIcon.icns" 2>/dev/null || true
fi

# Write Info.plist
cat > "$APP_BUNDLE/Contents/Info.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>SquirrelOps Home</string>
    <key>CFBundleDisplayName</key>
    <string>SquirrelOps Home</string>
    <key>CFBundleIdentifier</key>
    <string>com.squirrelops.home</string>
    <key>CFBundleVersion</key>
    <string>$APP_VERSION</string>
    <key>CFBundleShortVersionString</key>
    <string>$APP_VERSION</string>
    <key>SquirrelOpsDistributionVersion</key>
    <string>$DISTRIBUTION_VERSION</string>
    <key>CFBundleExecutable</key>
    <string>SquirrelOpsHome</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>14.0</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.utilities</string>
    <key>NSLocalNetworkUsageDescription</key>
    <string>SquirrelOps Home needs local network access to discover and communicate with the sensor.</string>
    <key>NSBonjourServices</key>
    <array>
        <string>_squirrelops._tcp</string>
    </array>
</dict>
</plist>
PLIST

echo "[+] Built: $APP_BUNDLE"
echo ""
echo "Run with:"
echo "  open $APP_BUNDLE"
