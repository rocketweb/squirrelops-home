#!/bin/bash
# Exact orphan teardown only. No installer invocation or global filter changes.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077

if [ "$(/usr/bin/id -u)" -ne 0 ] || [ "$#" -ne 0 ] || [ ! -t 0 ]; then
    echo "Run with sudo, without arguments, in an attended Terminal on the mini." >&2
    exit 1
fi
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
task_dir="$(/usr/bin/mktemp -d /private/var/root/squirrelops-mini-restart-cleanup.XXXXXXXX)"
for name in candidate.pkg mini_acceptance.py mini_upgrade_acceptance.py mini_ownership_acceptance.py mini_restart_cleanup.py; do
    if [ ! -f "$source_dir/$name" ] || [ -L "$source_dir/$name" ]; then
        echo "Missing or linked cleanup input: $name. Nothing stopped." >&2
        exit 1
    fi
    /usr/bin/install -o root -g wheel -m 600 "$source_dir/$name" "$task_dir/$name"
done
verify_digest() {
    local name="$1" expected="$2" actual
    actual="$(/usr/bin/shasum -a 256 "$task_dir/$name" | /usr/bin/awk '{print $1}')"
    if [ "$actual" != "$expected" ]; then
        echo "Checksum mismatch: $name. Nothing stopped." >&2
        exit 1
    fi
}
verify_digest candidate.pkg 2d5f4d287ca3ce971fd201f539d27a9272431f160a5a5debddc8d1b0b4dc7c82
verify_digest mini_acceptance.py 47b6c6df59083230ac63f97f1b32c55fa804f71839d433bfbc9fb952bf7bd40a
verify_digest mini_upgrade_acceptance.py 4c732720e89da4b4a872b56e951b1b70b121e2db603185ecb36d298c99c464d3
verify_digest mini_ownership_acceptance.py 98d8729e112e8ff48bbf320b094ab96471e597dd48cec6a726b17807d07986e6
verify_digest mini_restart_cleanup.py 007e70bab4bb8f741d48be009070aa240e823af795d4cd9fdda5a09bca306c6e

echo "Cleanup inputs verified. Preparing pinned private Python; no package installation."
/usr/sbin/pkgutil --expand-full "$task_dir/candidate.pkg" "$task_dir/expanded"
runtime="$task_dir/expanded/sensor.pkg/Payload/Library/SquirrelOps/sensor/python/bin/python3"
/usr/bin/codesign --verify --strict "$runtime"
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
    "$runtime" -I -B "$task_dir/mini_restart_cleanup.py" --run "$task_dir"
