#!/usr/bin/env bash
#
# build-sensor-venv.sh — Build a self-contained Python environment with the
# sensor package installed, suitable for embedding in the macOS .pkg installer.
#
# Strategy:
#   1. Check if a suitable Python 3.11+ is already installed on this machine
#   2. If found, create a venv from it (fast, small)
#   3. If not found, download a standalone Python from python-build-standalone
#      and install the sensor directly into it (no system Python needed)
#
# Usage:
#   bash scripts/build-sensor-venv.sh [output_dir]
#
# Arguments:
#   output_dir  Directory to create the Python environment in
#               (default: $REPO_ROOT/build/sensor-pkg)
#
# Environment:
#   BUILD_ARCH  Target architecture: "arm64", "x86_64", or "universal"
#               (default: current arch). Used when downloading standalone Python.
#
# The resulting layout (venv mode — system Python available):
#   $output_dir/
#     venv/          — Python venv with sensor installed
#     com.squirrelops.sensor.plist
#
# The resulting layout (standalone mode — no system Python):
#   $output_dir/
#     python/        — Standalone Python with sensor installed
#     com.squirrelops.sensor.plist
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve repo root
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SENSOR_DIR="$REPO_ROOT/sensor"
PLIST_TEMPLATE="$SENSOR_DIR/resources/com.squirrelops.sensor.plist"

OUTPUT_DIR="${1:-$REPO_ROOT/build/sensor-pkg}"
BUILD_ARCH="${BUILD_ARCH:-$(uname -m)}"

# ---------------------------------------------------------------------------
# Standalone Python configuration
# ---------------------------------------------------------------------------
# python-build-standalone from https://github.com/astral-sh/python-build-standalone
PBS_RELEASE="20260211"
PBS_PYTHON="3.12.12"

# Map macOS arch names to python-build-standalone arch names
case "$BUILD_ARCH" in
    arm64|universal)  PBS_ARCH="aarch64" ;;
    x86_64)           PBS_ARCH="x86_64" ;;
    *)                PBS_ARCH="aarch64" ;;
esac

PBS_FILENAME="cpython-${PBS_PYTHON}+${PBS_RELEASE}-${PBS_ARCH}-apple-darwin-install_only.tar.gz"
PBS_URL="https://github.com/astral-sh/python-build-standalone/releases/download/${PBS_RELEASE}/${PBS_FILENAME}"

# ---------------------------------------------------------------------------
# Colors
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
# Step 1: Check for system Python 3.11+
# ---------------------------------------------------------------------------
info "SquirrelOps Home Sensor — Environment Builder"
echo ""

PYTHON_CMD=""
for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        version=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")
        major=$(echo "$version" | cut -d. -f1)
        minor=$(echo "$version" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 11 ]; then
            PYTHON_CMD="$candidate"
            PYTHON_VERSION="$version"
            info "Found system Python $version at $(command -v "$candidate")"
            break
        fi
    fi
done

# ---------------------------------------------------------------------------
# Step 2: Validate sensor source
# ---------------------------------------------------------------------------
if [ ! -f "$SENSOR_DIR/pyproject.toml" ]; then
    error "Sensor pyproject.toml not found at $SENSOR_DIR/pyproject.toml"
fi

if [ ! -f "$PLIST_TEMPLATE" ]; then
    error "Plist template not found at $PLIST_TEMPLATE"
fi

# ---------------------------------------------------------------------------
# Step 3: Prepare output directory
# ---------------------------------------------------------------------------
mkdir -p "$OUTPUT_DIR"
info "Output directory: $OUTPUT_DIR"

# ---------------------------------------------------------------------------
# Step 4: Build the Python environment
# ---------------------------------------------------------------------------
if [ -n "$PYTHON_CMD" ]; then
    # -----------------------------------------------------------------------
    # Mode A: System Python available — create a venv (fast, small)
    # -----------------------------------------------------------------------
    info "Using system Python to create venv..."

    VENV_DIR="$OUTPUT_DIR/venv"
    if [ -d "$VENV_DIR" ]; then
        warn "Removing existing venv at $VENV_DIR"
        rm -rf "$VENV_DIR"
    fi

    "$PYTHON_CMD" -m venv "$VENV_DIR"
    VENV_PIP="$VENV_DIR/bin/pip"

    info "Upgrading pip, wheel, setuptools..."
    "$VENV_PIP" install --upgrade pip wheel setuptools --quiet

    info "Installing squirrelops-home-sensor from $SENSOR_DIR..."
    "$VENV_PIP" install "$SENSOR_DIR" --quiet

    # Write a marker so build-pkg.sh knows which mode was used
    echo "venv" > "$OUTPUT_DIR/.python-mode"

    ENV_SIZE=$(du -sh "$VENV_DIR" | cut -f1)
    ENV_PYTHON="$VENV_DIR/bin/python"
else
    # -----------------------------------------------------------------------
    # Mode B: No system Python — download standalone Python
    # -----------------------------------------------------------------------
    warn "No Python 3.11+ found on this machine."
    info "Downloading standalone Python ${PBS_PYTHON} (${PBS_ARCH})..."

    PYTHON_DIR="$OUTPUT_DIR/python"
    if [ -d "$PYTHON_DIR" ]; then
        warn "Removing existing standalone Python at $PYTHON_DIR"
        rm -rf "$PYTHON_DIR"
    fi

    # Download to a temp file, then extract
    TARBALL="$OUTPUT_DIR/${PBS_FILENAME}"
    if [ -f "$TARBALL" ]; then
        info "Using cached download: $TARBALL"
    else
        curl --fail --location --progress-bar -o "$TARBALL" "$PBS_URL" || {
            error "Failed to download standalone Python from: $PBS_URL"
        }
    fi

    info "Extracting standalone Python..."
    # The tarball extracts to a python/ directory
    tar -xzf "$TARBALL" -C "$OUTPUT_DIR"

    if [ ! -f "$PYTHON_DIR/bin/python3" ]; then
        error "Extraction failed: $PYTHON_DIR/bin/python3 not found"
    fi

    STANDALONE_PIP="$PYTHON_DIR/bin/python3 -m pip"
    PYTHON_VERSION=$("$PYTHON_DIR/bin/python3" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null)
    info "Standalone Python $PYTHON_VERSION ready."

    info "Installing squirrelops-home-sensor from $SENSOR_DIR..."
    "$PYTHON_DIR/bin/python3" -m pip install --upgrade pip --quiet
    "$PYTHON_DIR/bin/python3" -m pip install "$SENSOR_DIR" --quiet

    # Clean up the tarball to save space
    rm -f "$TARBALL"

    # Write a marker so build-pkg.sh knows which mode was used
    echo "standalone" > "$OUTPUT_DIR/.python-mode"

    ENV_SIZE=$(du -sh "$PYTHON_DIR" | cut -f1)
    ENV_PYTHON="$PYTHON_DIR/bin/python3"
fi

# ---------------------------------------------------------------------------
# Step 5: Copy launchd plist template
# ---------------------------------------------------------------------------
info "Copying launchd plist template..."
cp "$PLIST_TEMPLATE" "$OUTPUT_DIR/"

# ---------------------------------------------------------------------------
# Step 6: Summary
# ---------------------------------------------------------------------------
PYTHON_MODE=$(cat "$OUTPUT_DIR/.python-mode")

echo ""
echo -e "${BOLD}=========================================${NC}"
echo -e "${BOLD}  Sensor Environment Build Complete${NC}"
echo -e "${BOLD}=========================================${NC}"
echo ""
echo "  Mode:            $PYTHON_MODE"
echo "  Python version:  $PYTHON_VERSION"
echo "  Environment:     $ENV_PYTHON"
echo "  Size:            $ENV_SIZE"
echo "  Plist:           $OUTPUT_DIR/com.squirrelops.sensor.plist"
echo ""
echo "  Verify:  $ENV_PYTHON -c \"import squirrelops_home_sensor; print('OK')\""
echo ""
