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
#   SQUIRRELOPS_VERSION - override version (default: read from ../VERSION)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VERSION="${SQUIRRELOPS_VERSION:-$(cat "$SCRIPT_DIR/../VERSION")}"

APP_NAME="SquirrelOpsHome"
HELPER_NAME="SquirrelOpsHelper"
BUILD_CONFIG="${BUILD_CONFIG:-debug}"
BUILD_ARCH="${BUILD_ARCH:-$(uname -m)}"

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
cp "$BUILD_DIR/$APP_NAME" "$APP_BUNDLE/Contents/MacOS/$APP_NAME"

# Copy bundled resources (fonts etc.) using glob to handle naming variations
for bundle in "$BUILD_DIR"/*_"${APP_NAME}".bundle; do
    if [ -d "$bundle" ]; then
        cp -R "$bundle" "$APP_BUNDLE/Contents/Resources/"
    fi
done

# Copy helper binary into LaunchServices location if it exists
HELPER_BUNDLE_ID="com.squirrelops.helper"
if [ -f "$BUILD_DIR/$HELPER_NAME" ]; then
    echo "[+] Bundling helper: $HELPER_NAME -> $HELPER_BUNDLE_ID"
    mkdir -p "$APP_BUNDLE/Contents/Library/LaunchServices"
    cp "$BUILD_DIR/$HELPER_NAME" "$APP_BUNDLE/Contents/Library/LaunchServices/$HELPER_BUNDLE_ID"
else
    echo "[!] Helper binary not found at $BUILD_DIR/$HELPER_NAME — skipping"
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
    <string>$VERSION</string>
    <key>CFBundleShortVersionString</key>
    <string>$VERSION</string>
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
