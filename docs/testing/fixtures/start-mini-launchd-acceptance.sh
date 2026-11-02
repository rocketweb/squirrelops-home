#!/bin/bash
# Attended pinned upgrade/restart. No recovery writes or password handling.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077
if [ "$(/usr/bin/id -u)" -ne 0 ] || [ "$#" -ne 0 ] || [ ! -t 0 ]; then
    echo "Run with sudo and no arguments in Terminal on the mini." >&2
    exit 1
fi
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
task_dir="$(/usr/bin/mktemp -d /private/var/root/squirrelops-mini-launchd.XXXXXXXX)"
for name in candidate.pkg mini_acceptance.py mini_upgrade_acceptance.py mini_ownership_acceptance.py mini_launchd_acceptance.py approved-scope.md; do
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
verify_digest candidate.pkg 3a3cda47a7eaec1a015edd82ad42edc91be10b64d181a805d29f114f2357893c
verify_digest mini_acceptance.py 46f441987cf092c0cf4cb38eb6b76bbef1452eca54d66b37ff1e98523a2dcb3f
verify_digest mini_upgrade_acceptance.py bb5e7b1c8155f7301f25139e6bd6091a3d5c116f6dc4efe39207937b08e3ae5a
verify_digest mini_ownership_acceptance.py 1edd5706b7dd5f0fc8285b50ce2d895a9952208218c19d1ddf66934715191287
verify_digest mini_launchd_acceptance.py d03b69614bfb1cfae3eb4e545ac54717b083361ced1cdc12ffab5cd45a6e91f0
verify_digest approved-scope.md 8c9f8bd39f41f32fab7dc9869770bf426def7d31f7fc9c70bab3d357aafb09cd

echo "Shutdown-budget inputs verified. Preparing the pinned private Python runtime."
/usr/sbin/pkgutil --expand-full "$task_dir/candidate.pkg" "$task_dir/expanded"
runtime="$task_dir/expanded/sensor.pkg/Payload/Library/SquirrelOps/sensor/python/bin/python3.12"
/usr/bin/codesign --verify --strict "$runtime"
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
    "$runtime" -I -B "$task_dir/mini_launchd_acceptance.py" --run "$task_dir"
