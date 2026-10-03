#!/bin/bash
# One approved, attended, data-preserving upgrade on 192.168.1.97 only.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077
if [ "$(/usr/bin/id -u)" -ne 0 ] || [ "$#" -ne 0 ] || [ ! -t 0 ]; then
    echo 'Run with sudo and no arguments in Terminal on the MacBook.' >&2
    exit 1
fi
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
task_dir="$(/usr/bin/mktemp -d /private/var/root/squirrelops-macbook-upgrade.XXXXXXXX)"
for name in candidate.pkg old.pkg macbook_upgrade.py mini_clean_upgrade.py; do
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
verify_digest candidate.pkg 669e4b2b5762f819b4b07c4f5cddc5b6797bae4cd7519282280ee049d3533c17
verify_digest old.pkg 252bd6bd559b4dbf578410aa959611675d3b627163ee885f404857cb67ab23f8
verify_digest macbook_upgrade.py 3c361ad888be5f35ce087a1c15f97ddfcd8f73279781672bdcfd10d2eba555a9
verify_digest mini_clean_upgrade.py 90504c8a7a1f422e5692bac138ecd7e15f5ad0479cb51579f2f4284cd065afe0
echo 'Pinned upgrade inputs verified. Preparing private Python; no product change yet.'
/usr/sbin/pkgutil --expand-full "$task_dir/candidate.pkg" "$task_dir/expanded"
runtime="$task_dir/expanded/sensor.pkg/Payload/Library/SquirrelOps/sensor/python/bin/python3.12"
/usr/bin/codesign --verify --strict "$runtime"
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
    "$runtime" -I -B "$task_dir/macbook_upgrade.py" --run "$task_dir"
