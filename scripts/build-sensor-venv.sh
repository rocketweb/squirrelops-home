#!/usr/bin/env bash
#
# build-sensor-venv.sh — Build a self-contained Python venv with the sensor
# package installed, suitable for embedding in the macOS .pkg installer.
#
# Usage:
#   bash scripts/build-sensor-venv.sh [output_dir]
#
# Arguments:
#   output_dir  Directory to create venv and copy plist into (default: $REPO_ROOT/build/sensor-pkg)
#
# The resulting layout:
#   $output_dir/
#     venv/          — Self-contained Python venv with squirrelops-home-sensor installed
#     com.squirrelops.sensor.plist — launchd plist template
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve repo root (works regardless of where the script is invoked from)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SENSOR_DIR="$REPO_ROOT/sensor"
PLIST_TEMPLATE="$SENSOR_DIR/resources/com.squirrelops.sensor.plist"

# Output directory: first argument or default
OUTPUT_DIR="${1:-$REPO_ROOT/build/sensor-pkg}"

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
# Step 1: Find Python 3.11+
# ---------------------------------------------------------------------------
info "SquirrelOps Home Sensor — Venv Builder"
echo ""

PYTHON_CMD=""
for candidate in python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        version=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")
        major=$(echo "$version" | cut -d. -f1)
        minor=$(echo "$version" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 11 ]; then
            PYTHON_CMD="$candidate"
            PYTHON_VERSION="$version"
            info "Found Python $version at $(command -v "$candidate")"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    error "Python 3.11+ is required but not found. Install via: brew install python@3.12"
fi

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
VENV_DIR="$OUTPUT_DIR/venv"

if [ -d "$VENV_DIR" ]; then
    warn "Removing existing venv at $VENV_DIR"
    rm -rf "$VENV_DIR"
fi

mkdir -p "$OUTPUT_DIR"
info "Output directory: $OUTPUT_DIR"

# ---------------------------------------------------------------------------
# Step 4: Create venv
# ---------------------------------------------------------------------------
info "Creating Python venv..."
"$PYTHON_CMD" -m venv "$VENV_DIR"

VENV_PYTHON="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

# ---------------------------------------------------------------------------
# Step 5: Upgrade pip, wheel, setuptools
# ---------------------------------------------------------------------------
info "Upgrading pip, wheel, setuptools..."
"$VENV_PIP" install --upgrade pip wheel setuptools --quiet

# ---------------------------------------------------------------------------
# Step 6: Install sensor package from local source
# ---------------------------------------------------------------------------
info "Installing squirrelops-home-sensor from $SENSOR_DIR..."
"$VENV_PIP" install "$SENSOR_DIR" --quiet

# ---------------------------------------------------------------------------
# Step 7: Copy launchd plist template
# ---------------------------------------------------------------------------
info "Copying launchd plist template..."
cp "$PLIST_TEMPLATE" "$OUTPUT_DIR/"

# ---------------------------------------------------------------------------
# Step 8: Summary
# ---------------------------------------------------------------------------
VENV_SIZE=$(du -sh "$VENV_DIR" | cut -f1)

echo ""
echo -e "${BOLD}=========================================${NC}"
echo -e "${BOLD}  Sensor Venv Build Complete${NC}"
echo -e "${BOLD}=========================================${NC}"
echo ""
echo "  Python version:  $PYTHON_VERSION"
echo "  Venv path:       $VENV_DIR"
echo "  Venv size:       $VENV_SIZE"
echo "  Plist:           $OUTPUT_DIR/com.squirrelops.sensor.plist"
echo ""
echo "  Verify:  $VENV_PYTHON -c \"import squirrelops_home_sensor; print('OK')\""
echo ""
