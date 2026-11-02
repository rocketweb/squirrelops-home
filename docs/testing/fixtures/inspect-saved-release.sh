#!/bin/bash
# Read completed private evidence only. No service, network or installer calls.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077
if [ "$(/usr/bin/id -u)" -ne 0 ] || [ "$#" -ne 1 ] || [ ! -t 0 ]; then
    echo 'Use sudo in Terminal with one argument: macbook or mini.' >&2
    exit 1
fi
case "$1" in
    macbook) runtime=/Library/SquirrelOps/sensor/python/bin/python3.12 ;;
    mini) runtime=/usr/bin/python3 ;;
    *) echo 'Only the pinned MacBook and Mini archives are in scope.' >&2; exit 1 ;;
esac
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
task_dir="$(/usr/bin/mktemp -d /private/var/root/squirrelops-release-review.XXXXXXXX)"
for name in inspect_saved_release.py inspect_completed.py; do
    if [ ! -f "$source_dir/$name" ] || [ -L "$source_dir/$name" ]; then
        echo "Missing or linked input: $name. No evidence read." >&2
        exit 1
    fi
    /usr/bin/install -o root -g wheel -m 600 "$source_dir/$name" "$task_dir/$name"
done
verify_digest() {
    local name="$1" expected="$2" actual
    actual="$(/usr/bin/shasum -a 256 "$task_dir/$name" | /usr/bin/awk '{print $1}')"
    if [ "$actual" != "$expected" ]; then
        echo "Checksum mismatch: $name. No evidence read." >&2
        exit 1
    fi
}
verify_digest inspect_saved_release.py 254e57308dfe4ed81264aa6e1c16144fc8dc82ec8cf6e0c7e8deecd86761ee1f
verify_digest inspect_completed.py b52ac6d84567b7a10bdf33664803451aa6dd80d6eeb96dd155fef5a4404cbd92
echo 'Pinned read-only inputs verified. Reading completed private evidence only.'
echo 'No services, installed data, network probes, firewall rules or permissions will change.'
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
    "$runtime" -I -B "$task_dir/inspect_saved_release.py" "$1" --run
