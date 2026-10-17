#!/bin/bash
# Attended post-reboot install/restart. Historical runners are never executed.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077
if [ "$(/usr/bin/id -u)" -ne 0 ] || [ "$#" -ne 0 ] || [ ! -t 0 ]; then
    echo "Run with sudo and no arguments in Terminal on the mini." >&2
    exit 1
fi
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
task_dir="$(/usr/bin/mktemp -d /private/var/root/squirrelops-mini-post-reboot.XXXXXXXX)"
for name in candidate.pkg mini_acceptance.py mini_upgrade_acceptance.py mini_ownership_acceptance.py mini_launchd_acceptance.py mini_single_ip_acceptance.py mini_post_reboot_acceptance.py single-ip-config.yaml approved-scope.md; do
    if [ ! -f "$source_dir/$name" ] || [ -L "$source_dir/$name" ]; then
        echo "Missing or linked input: $name. No configuration change or install attempted." >&2
        exit 1
    fi
    /usr/bin/install -o root -g wheel -m 600 "$source_dir/$name" "$task_dir/$name"
done
verify_digest() {
    local name="$1" expected="$2" actual
    actual="$(/usr/bin/shasum -a 256 "$task_dir/$name" | /usr/bin/awk '{print $1}')"
    if [ "$actual" != "$expected" ]; then
        echo "Checksum mismatch: $name. No configuration change or install attempted." >&2
        exit 1
    fi
}
verify_digest candidate.pkg 3a3cda47a7eaec1a015edd82ad42edc91be10b64d181a805d29f114f2357893c
verify_digest mini_acceptance.py 47b6c6df59083230ac63f97f1b32c55fa804f71839d433bfbc9fb952bf7bd40a
verify_digest mini_upgrade_acceptance.py 4c732720e89da4b4a872b56e951b1b70b121e2db603185ecb36d298c99c464d3
verify_digest mini_ownership_acceptance.py 98d8729e112e8ff48bbf320b094ab96471e597dd48cec6a726b17807d07986e6
verify_digest mini_launchd_acceptance.py 7b2517b3c59fff71741be115267b1687e50c26c5e48c40b903bb3bfdebffa6ba
verify_digest mini_single_ip_acceptance.py 3a37156ff54ee8e0086b84036cbe155f4758509d93471047e6a28262e165e943
verify_digest mini_post_reboot_acceptance.py b97147d63a35f8a7b93eade3f01c7a2dfc03a80a6f09b3c29cec7156885cc068
verify_digest single-ip-config.yaml 6b492246632eee7bc3975e84fc7c75699d3dcdfc15f2ec542ec673ab243b4bd8
verify_digest approved-scope.md 288eb8eb45a50caaac9538f02ac1cc23ca697573e967771a06314cfb2725f24e

echo "Post-reboot inputs verified. Preparing pinned private Python; no product change yet."
/usr/sbin/pkgutil --expand-full "$task_dir/candidate.pkg" "$task_dir/expanded"
runtime="$task_dir/expanded/sensor.pkg/Payload/Library/SquirrelOps/sensor/python/bin/python3.12"
/usr/bin/codesign --verify --strict "$runtime"
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
    "$runtime" -I -B "$task_dir/mini_post_reboot_acceptance.py" --run "$task_dir"
