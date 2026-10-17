#!/bin/bash
# One attended, approved upgrade. No password handling or general command runner.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077
if [ "$(/usr/bin/id -u)" -ne 0 ] || [ "$#" -ne 0 ] || [ ! -t 0 ]; then
    echo "Run with sudo and no arguments in Terminal on the mini." >&2
    exit 1
fi

source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
task_dir="$(/usr/bin/mktemp -d /private/var/root/squirrelops-mini-upgrade.XXXXXXXX)"
for name in candidate.pkg mini_acceptance.py mini_upgrade_acceptance.py approved-scope.md; do
    if [ ! -f "$source_dir/$name" ] || [ -L "$source_dir/$name" ]; then
        echo "Missing or linked input: $name. No installation attempted." >&2
        exit 1
    fi
    /usr/bin/install -o root -g wheel -m 600 "$source_dir/$name" "$task_dir/$name"
done
verify_digest() {
    local name="$1" expected="$2" actual
    actual="$(/usr/bin/shasum -a 256 "$task_dir/$name" | /usr/bin/awk '{print $1}')"
    if [ "$actual" != "$expected" ]; then
        echo "Checksum mismatch: $name. No installation attempted." >&2
        exit 1
    fi
}
verify_digest candidate.pkg 541fc783c41fd2f9a6baba1fe8edae93078a0a24089b8e6d4ede77ba051b7fb1
verify_digest mini_acceptance.py 47b6c6df59083230ac63f97f1b32c55fa804f71839d433bfbc9fb952bf7bd40a
verify_digest mini_upgrade_acceptance.py c61154c3b6b62cc945c62aae58eb0c6bfe259305539ef604a36708b52e098110
verify_digest approved-scope.md 783395f91247dc2997db4af96515503a7f20222d0e6781a55a2b222e8d229648

echo "Upgrade inputs verified. Preparing the pinned private Python runtime."
/usr/sbin/pkgutil --expand-full "$task_dir/candidate.pkg" "$task_dir/expanded"
runtime="$task_dir/expanded/sensor.pkg/Payload/Library/SquirrelOps/sensor/python/bin/python3.12"
/usr/bin/codesign --verify --strict "$runtime"
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
    "$runtime" -I -B "$task_dir/mini_upgrade_acceptance.py" --run "$task_dir"
