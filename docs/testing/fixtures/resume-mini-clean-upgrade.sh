#!/bin/bash
# Resume only the reviewed partial uninstall; retain the original archive.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077
if [ "$(/usr/bin/id -u)" -ne 0 ] || [ "$#" -ne 0 ] || [ ! -t 0 ]; then
    echo "Run with sudo and no arguments in Terminal on the Mini." >&2
    exit 1
fi
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
task_dir="$(/usr/bin/mktemp -d /private/var/root/squirrelops-mini-clean-resume.XXXXXXXX)"
for name in old.pkg current.pkg mini_clean_upgrade.py mini_resume_clean_upgrade.py uninstall-fixed.sh; do
    if [ ! -f "$source_dir/$name" ] || [ -L "$source_dir/$name" ]; then
        echo "Missing or linked input: $name. No product change attempted." >&2
        exit 1
    fi
    /usr/bin/install -o root -g wheel -m 600 "$source_dir/$name" "$task_dir/$name"
done
verify_digest() {
    local name="$1" expected="$2" actual
    actual="$(/usr/bin/shasum -a 256 "$task_dir/$name" | /usr/bin/awk '{print $1}')"
    if [ "$actual" != "$expected" ]; then
        echo "Checksum mismatch: $name. No product change attempted." >&2
        exit 1
    fi
}
verify_digest old.pkg 252bd6bd559b4dbf578410aa959611675d3b627163ee885f404857cb67ab23f8
verify_digest current.pkg 47774088cd9eadc5aaddf38949e00a8b8f6eeb56c2192a5a72830d06d84a8aec
verify_digest mini_clean_upgrade.py 90504c8a7a1f422e5692bac138ecd7e15f5ad0479cb51579f2f4284cd065afe0
verify_digest mini_resume_clean_upgrade.py 9aafd26e22f9bdb2bb4b66e7f9d71c7cd023f278856a8ea50b160c1c70db300e
verify_digest uninstall-fixed.sh 1f2e64b73b20db7cbacf5caf9ac0d79053c7a1db754684dbc96b4e6a9f3166b6
echo "Resume inputs verified. Preparing private Python; no cleanup performed yet."
/usr/sbin/pkgutil --expand-full "$task_dir/current.pkg" "$task_dir/expanded"
runtime="$task_dir/expanded/sensor.pkg/Payload/Library/SquirrelOps/sensor/python/bin/python3.12"
/usr/bin/codesign --verify --strict "$runtime"
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
    "$runtime" -I -B "$task_dir/mini_resume_clean_upgrade.py" --run "$task_dir"
