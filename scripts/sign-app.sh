#!/usr/bin/env bash
#
# SquirrelOps Home — Code Signing Script
#
# Signs the .app bundle and embedded helper for distribution.
# Gracefully skips if the signing identity is not found (local dev).
#
# Usage:
#   bash scripts/sign-app.sh <path-to.app> [signing-identity]
#
# Arguments:
#   <path-to.app>      Path to the built .app bundle (required)
#   [signing-identity]  Code signing identity (default: "Developer ID Application")
#
# Examples:
#   bash scripts/sign-app.sh app/.build/arm64-apple-macosx/debug/SquirrelOpsHome.app
#   bash scripts/sign-app.sh build/SquirrelOpsHome.app "Developer ID Application: My Team (XXXXXXXXXX)"
#
set -euo pipefail

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

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------
if [ $# -lt 1 ]; then
    echo "Usage: $0 <path-to.app> [signing-identity]"
    exit 1
fi

APP_BUNDLE="$1"
IDENTITY="${2:-Developer ID Application}"

# Resolve paths relative to the repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

APP_ENTITLEMENTS="$REPO_ROOT/app/entitlements/app.entitlements"
HELPER_ENTITLEMENTS="$REPO_ROOT/app/entitlements/helper.entitlements"

HELPER_BUNDLE_ID="com.squirrelops.helper"
HELPER_PATH="$APP_BUNDLE/Contents/Library/LaunchServices/$HELPER_BUNDLE_ID"

# ---------------------------------------------------------------------------
# Validate inputs
# ---------------------------------------------------------------------------
if [ ! -d "$APP_BUNDLE" ]; then
    error "App bundle not found: $APP_BUNDLE"
fi

if [ ! -f "$APP_ENTITLEMENTS" ]; then
    error "App entitlements not found: $APP_ENTITLEMENTS"
fi

if [ ! -f "$HELPER_ENTITLEMENTS" ]; then
    error "Helper entitlements not found: $HELPER_ENTITLEMENTS"
fi

# ---------------------------------------------------------------------------
# Check signing identity
# ---------------------------------------------------------------------------
info "Checking for signing identity: ${BOLD}$IDENTITY${NC}"

if ! security find-identity -v -p codesigning | grep -q "$IDENTITY"; then
    warn "Signing identity '$IDENTITY' not found in Keychain."
    warn "Skipping code signing (this is expected for local dev builds)."
    exit 0
fi

info "Signing identity found."

# ---------------------------------------------------------------------------
# Step 1: Sign the helper binary (inside-out signing order)
# ---------------------------------------------------------------------------
if [ -f "$HELPER_PATH" ]; then
    info "Signing helper binary: $HELPER_PATH"
    codesign --force \
        --options runtime \
        --entitlements "$HELPER_ENTITLEMENTS" \
        --sign "$IDENTITY" \
        --timestamp \
        "$HELPER_PATH"
    info "Helper signed successfully."
else
    warn "Helper binary not found at $HELPER_PATH — skipping helper signing."
fi

# ---------------------------------------------------------------------------
# Step 2: Sign the app bundle
# ---------------------------------------------------------------------------
info "Signing app bundle: $APP_BUNDLE"
codesign --force \
    --options runtime \
    --deep \
    --entitlements "$APP_ENTITLEMENTS" \
    --sign "$IDENTITY" \
    --timestamp \
    "$APP_BUNDLE"
info "App bundle signed successfully."

# ---------------------------------------------------------------------------
# Step 3: Verify signature
# ---------------------------------------------------------------------------
info "Verifying signature..."
codesign --verify --verbose=2 "$APP_BUNDLE"
info "Signature verification passed."

# ---------------------------------------------------------------------------
# Step 4: Gatekeeper assessment (may fail for non-notarized builds)
# ---------------------------------------------------------------------------
info "Running Gatekeeper assessment (spctl)..."
if spctl --assess --type execute --verbose=2 "$APP_BUNDLE" 2>&1; then
    info "Gatekeeper assessment passed."
else
    warn "Gatekeeper assessment failed (expected for non-notarized builds)."
fi

echo ""
info "Code signing complete: $APP_BUNDLE"
