#!/usr/bin/env bash
#
# Remove build-host artifacts from the standalone Python runtime embedded in
# the macOS package, or validate an already-staged payload without changing it.
#
# Usage:
#   sanitize-python-runtime.sh sanitize <payload-dir> <forbidden-path> [...]
#   sanitize-python-runtime.sh validate <payload-dir> <forbidden-path> [...]
#
set -euo pipefail

readonly INSTALLED_PYTHON="/Library/SquirrelOps/sensor/python/bin/python3"

fail() {
    echo "[python-runtime] $*" >&2
    exit 1
}

if [ "$#" -lt 3 ]; then
    fail "Usage: $0 <sanitize|validate> <payload-dir> <forbidden-path> [...]"
fi

MODE="$1"
PAYLOAD_DIR="$2"
shift 2

case "$MODE" in
    sanitize|validate) ;;
    *) fail "Unsupported mode: $MODE" ;;
esac

if [ ! -d "$PAYLOAD_DIR" ] || [ "$PAYLOAD_DIR" = "/" ]; then
    fail "Payload directory is missing or unsafe: $PAYLOAD_DIR"
fi

if [ "$MODE" = "sanitize" ]; then
    PAYLOAD_REAL="$(cd "$PAYLOAD_DIR" && pwd -P)"
    if [ "$(basename "$PAYLOAD_REAL")" != "python" ] \
        || [ ! -x "$PAYLOAD_REAL/bin/python3" ] \
        || [ ! -d "$PAYLOAD_REAL/lib" ]; then
        fail "Python runtime target is unsafe or incomplete: $PAYLOAD_DIR"
    fi
    PAYLOAD_DIR="$PAYLOAD_REAL"

    while IFS= read -r -d '' cache_dir; do
        rm -rf -- "$cache_dir"
    done < <(find "$PAYLOAD_DIR" -type d -name "__pycache__" -prune -print0)

    find "$PAYLOAD_DIR" -type f -name "*.pyc" -delete
    find "$PAYLOAD_DIR" -type f -name "direct_url.json" -delete

    while IFS= read -r -d '' console_script; do
        magic="$(od -An -t x1 -N 2 "$console_script" | tr -d '[:space:]')"
        if [ "$magic" != "2321" ]; then
            continue
        fi
        first_line="$(sed -n '1p' "$console_script")"
        case "$first_line" in
            "#!"*python*)
                sed -i '' -e "1s|^.*|#!${INSTALLED_PYTHON}|" "$console_script"
                ;;
        esac
    done < <(find "$PAYLOAD_DIR/bin" -maxdepth 1 -type f -print0)
fi

while IFS= read -r -d '' payload_file; do
    for forbidden_path in "$@"; do
        if [ -z "$forbidden_path" ] || [ "$forbidden_path" = "/" ]; then
            fail "Forbidden build path is empty or unsafe."
        fi
        if LC_ALL=C grep -a -F -q -- "$forbidden_path" "$payload_file"; then
            fail "Build-host path remains in payload file: $payload_file"
        fi
    done
done < <(find "$PAYLOAD_DIR" -type f -print0)
