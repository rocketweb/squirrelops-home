#!/bin/bash
# One attended diagnostic. No installation, PF changes, services or packet capture.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077

if [ "$(/usr/bin/id -u)" -ne 0 ] || [ "$#" -ne 0 ] || [ ! -t 0 ]; then
    echo "Run with sudo, without arguments, in an attended Terminal on the mini." >&2
    exit 1
fi

source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
task_dir="$(/usr/bin/mktemp -d /private/var/root/squirrelops-tcp-diag.XXXXXXXX)"
for name in mini_tcp_diagnostic.py approved-scope.md; do
    if [ ! -f "$source_dir/$name" ] || [ -L "$source_dir/$name" ]; then
        echo "Missing or linked diagnostic input: $name. No probe started." >&2
        exit 1
    fi
    /usr/bin/install -o root -g wheel -m 600 "$source_dir/$name" "$task_dir/$name"
done

verify_digest() {
    local name="$1" expected="$2" actual
    actual="$(/usr/bin/shasum -a 256 "$task_dir/$name" | /usr/bin/awk '{print $1}')"
    if [ "$actual" != "$expected" ]; then
        echo "Checksum mismatch: $name. No probe started." >&2
        exit 1
    fi
}
verify_digest mini_tcp_diagnostic.py 8d3330aca67038485c0b8cf9ede00c8cb1864cc60363455a39ac7f4c2001d370
verify_digest approved-scope.md 6f75109eb6cc4bb633411e47522638b8958cc1cc3fb7c148515fb54063471b61

echo "Inputs verified. Checking the stopped mini baseline; no installer or filter changes."
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
    /usr/bin/python3 -I -S -B "$task_dir/mini_tcp_diagnostic.py" --run "$task_dir"
