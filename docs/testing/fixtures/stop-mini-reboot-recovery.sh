#!/bin/bash
# Durable, pinned, attended recovery only. Never install or reset networking.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077
if [ "$(/usr/bin/id -u)" -ne 0 ] || [ "$#" -ne 0 ] || [ ! -t 0 ]; then
    echo "Run with sudo and no arguments in Terminal on the mini." >&2
    exit 1
fi
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
backup_root=/Library/SquirrelOps/acceptance-backups
runtime=/Library/SquirrelOps/sensor/python/bin/python3.12
for directory in /Library /Library/SquirrelOps "$backup_root" /Library/SquirrelOps/sensor /Library/SquirrelOps/sensor/python /Library/SquirrelOps/sensor/python/bin; do
    if [ ! -d "$directory" ] || [ -L "$directory" ]; then
        echo "Unsafe existing directory; no recovery attempted." >&2
        exit 1
    fi
    metadata="$(/usr/bin/stat -f '%u:%g:%OLp' "$directory")"
    case "$metadata" in
        0:0:700|0:0:750|0:0:755|0:0:711) ;;
        *) echo "Existing root-directory ownership/mode requires review: $directory" >&2; exit 1 ;;
    esac
done
if [ ! -f "$runtime" ] || [ -L "$runtime" ] || [ "$(/usr/bin/stat -f '%u:%g' "$runtime")" != 0:0 ]; then
    echo "Installed private runtime identity requires review." >&2
    exit 1
fi
runtime_sha="$(/usr/bin/shasum -a 256 "$runtime" | /usr/bin/awk '{print $1}')"
if [ "$runtime_sha" != d2555cd22a33506826f9eb069bb13fb0cc41303c7da41da5b761967d616f4147 ]; then
    echo "Installed private runtime hash changed; no recovery attempted." >&2
    exit 1
fi
/usr/bin/codesign --verify --strict "$runtime"
task_dir="$(/usr/bin/mktemp -d "$backup_root/mini-reboot-20260930.XXXXXXXX")"
for name in mini_acceptance.py mini_upgrade_acceptance.py mini_ownership_acceptance.py mini_launchd_acceptance.py mini_reboot_recovery.py approved-scope.md; do
    if [ ! -f "$source_dir/$name" ] || [ -L "$source_dir/$name" ]; then
        echo "Missing or linked input: $name. No product changes attempted." >&2
        exit 1
    fi
    /usr/bin/install -o root -g wheel -m 600 "$source_dir/$name" "$task_dir/$name"
done
verify_digest() {
    local name="$1" expected="$2" actual
    actual="$(/usr/bin/shasum -a 256 "$task_dir/$name" | /usr/bin/awk '{print $1}')"
    if [ "$actual" != "$expected" ]; then
        echo "Checksum mismatch: $name. No product changes attempted." >&2
        exit 1
    fi
}
verify_digest mini_acceptance.py 46f441987cf092c0cf4cb38eb6b76bbef1452eca54d66b37ff1e98523a2dcb3f
verify_digest mini_upgrade_acceptance.py bb5e7b1c8155f7301f25139e6bd6091a3d5c116f6dc4efe39207937b08e3ae5a
verify_digest mini_ownership_acceptance.py 1edd5706b7dd5f0fc8285b50ce2d895a9952208218c19d1ddf66934715191287
verify_digest mini_launchd_acceptance.py d03b69614bfb1cfae3eb4e545ac54717b083361ced1cdc12ffab5cd45a6e91f0
verify_digest mini_reboot_recovery.py 9632faaac479ab98898191ef1866117bb8f2982a55759446ec796d8561ee4048
verify_digest approved-scope.md c9fc034e585acdb925fc2db6e26b4c9775105ea668d64c2bb35eba92f3e0fe0e
echo "Recovery inputs verified. No installer or Little Snitch changes. Durable evidence: $task_dir"
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
    "$runtime" -I -B "$task_dir/mini_reboot_recovery.py" --run "$task_dir"
