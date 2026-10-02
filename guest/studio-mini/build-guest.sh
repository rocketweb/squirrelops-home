#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TARGET_ARCH="${1:-$(uname -m)}"
ALPINE_IMAGE="${ALPINE_IMAGE:-alpine:3.24.1}"

case "$TARGET_ARCH" in
    arm64)
        DOCKER_PLATFORM=linux/arm64
        ;;
    x86_64)
        DOCKER_PLATFORM=linux/amd64
        ;;
    *)
        echo "Unsupported guest architecture: $TARGET_ARCH" >&2
        exit 1
        ;;
esac

if [ "${SQUIRRELOPS_RELEASE_BUILD:-0}" = "1" ] && [[ "$ALPINE_IMAGE" != *@sha256:* ]]; then
    echo "Release guest builds require ALPINE_IMAGE pinned by digest." >&2
    exit 1
fi

OUTPUT_DIR="$SCRIPT_DIR/build/$TARGET_ARCH"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

docker buildx build \
    --platform "$DOCKER_PLATFORM" \
    --build-arg "ALPINE_IMAGE=$ALPINE_IMAGE" \
    --output "type=local,dest=$TEMP_DIR" \
    "$SCRIPT_DIR"

test -s "$TEMP_DIR/vmlinuz"
test -s "$TEMP_DIR/studio-mini.initramfs"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"
cp "$TEMP_DIR/vmlinuz" "$OUTPUT_DIR/vmlinuz"
cp "$TEMP_DIR/studio-mini.initramfs" "$OUTPUT_DIR/studio-mini.initramfs"
chmod 0644 "$OUTPUT_DIR/vmlinuz" "$OUTPUT_DIR/studio-mini.initramfs"

KERNEL_SHA="$(shasum -a 256 "$OUTPUT_DIR/vmlinuz" | awk '{print $1}')"
INITRAMFS_SHA="$(shasum -a 256 "$OUTPUT_DIR/studio-mini.initramfs" | awk '{print $1}')"
printf '%s\n' \
    '{' \
    '  "schema_version": 1,' \
    '  "persona_id": "studio-mini-v1",' \
    '  "boot": {' \
    "    \"kernel\": {\"path\": \"vmlinuz\", \"sha256\": \"$KERNEL_SHA\"}," \
    "    \"initial_ramdisk\": {\"path\": \"studio-mini.initramfs\", \"sha256\": \"$INITRAMFS_SHA\"}," \
    '    "command_line": "console=hvc0 rdinit=/sbin/init"' \
    '  },' \
    '  "resources": {"cpu_count": 2, "memory_bytes": 1073741824, "max_connections": 16},' \
    '  "containment": {' \
    '    "network_devices": 0,' \
    '    "host_shares": [],' \
    '    "clipboard": false,' \
    '    "egress": "none",' \
    '    "root_filesystem": "memory-only"' \
    '  },' \
    '  "services": [' \
    '    {"name": "ssh", "advertised_port": 22, "guest_vsock_port": 10022},' \
    '    {"name": "smb", "advertised_port": 445, "guest_vsock_port": 10445}' \
    '  ]' \
    '}' > "$OUTPUT_DIR/manifest.json"
chmod 0644 "$OUTPUT_DIR/manifest.json"

python3 "$REPO_ROOT/scripts/verify-guest-bundle.py" "$OUTPUT_DIR" \
    --architecture "$TARGET_ARCH"
echo "Built Studio Mini guest bundle: $OUTPUT_DIR"
