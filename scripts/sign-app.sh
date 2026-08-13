#!/usr/bin/env bash
#
# SquirrelOps Home — Code Signing Script
#
# Signs the .app bundle and embedded helper for distribution. Local builds
# gracefully skip a missing identity; release builds fail closed.
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
if [ "$IDENTITY" = "-" ] && [ "$LOCAL_TEST_BUILD" != "1" ]; then
    error "Ad-hoc signing is restricted to explicit local test builds."
fi
if [ "$LOCAL_TEST_BUILD" = "1" ] && [ "$RELEASE_BUILD" = "1" ]; then
    error "A release build cannot be a local test build."
fi

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
if [ ! -x "$HELPER_PATH" ]; then
    error "Required helper binary is missing or not executable: $HELPER_PATH"
fi

# ---------------------------------------------------------------------------
# Check signing identity
# ---------------------------------------------------------------------------
info "Checking for signing identity: ${BOLD}$IDENTITY${NC}"

if [ "$IDENTITY" != "-" ] \
    && ! security find-identity -v -p codesigning | grep -Fq -- "$IDENTITY"; then
    if [ "$RELEASE_BUILD" = "1" ]; then
        error "Release builds require an available app signing identity: $IDENTITY"
    fi
    warn "Signing identity '$IDENTITY' not found in Keychain."
    warn "Skipping code signing (this is expected for local dev builds)."
    exit 0
fi

info "Signing identity found."

USE_TIMESTAMP=1
if [ "$IDENTITY" = "-" ]; then
    USE_TIMESTAMP=0
    warn "Using an ad-hoc signature for an explicit local test build."
fi

# ---------------------------------------------------------------------------
# Step 1: Sign the helper binary (inside-out signing order)
# ---------------------------------------------------------------------------
info "Signing helper binary: $HELPER_PATH"
HELPER_SIGN_ARGS=(
    codesign --force
    --options runtime
    --identifier "$HELPER_BUNDLE_ID"
    --entitlements "$HELPER_ENTITLEMENTS"
    --sign "$IDENTITY"
)
if [ "$USE_TIMESTAMP" = "1" ]; then
    HELPER_SIGN_ARGS+=(--timestamp)
fi
HELPER_SIGN_ARGS+=("$HELPER_PATH")
"${HELPER_SIGN_ARGS[@]}"
if ! HELPER_SIGNATURE="$(codesign -d --verbose=4 "$HELPER_PATH" 2>&1)"; then
    error "Could not read the helper signature."
fi
# Do not pipe codesign into grep -q under pipefail: grep closes the pipe after
# the first match, which can make codesign exit on SIGPIPE and turn a valid
# signature into a false build failure.
if ! grep -Fxq "Identifier=${HELPER_BUNDLE_ID}" <<< "$HELPER_SIGNATURE"; then
    error "Helper signature identifier is not ${HELPER_BUNDLE_ID}."
fi
info "Helper signed successfully."

# ---------------------------------------------------------------------------
# Step 2: Sign the app bundle
# ---------------------------------------------------------------------------
info "Signing app bundle: $APP_BUNDLE"
APP_SIGN_ARGS=(
    codesign --force
    --options runtime
    --deep
    --entitlements "$APP_ENTITLEMENTS"
    --sign "$IDENTITY"
)
if [ "$USE_TIMESTAMP" = "1" ]; then
    APP_SIGN_ARGS+=(--timestamp)
fi
APP_SIGN_ARGS+=("$APP_BUNDLE")
"${APP_SIGN_ARGS[@]}"
info "App bundle signed successfully."

# ---------------------------------------------------------------------------
# Step 3: Verify signature
# ---------------------------------------------------------------------------
info "Verifying signature..."
codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE"
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
