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
verify_digest mini_tcp_diagnostic.py 26d36c3eb53630dd0c3ec104ddbf0d61d75a8c03b9facae3bb8aa06dfce8b403
verify_digest approved-scope.md 8c16143c93d67bd5b09eb79909c748e62e2c319a246e42105241212a6a3427d4

echo "Inputs verified. Checking the stopped mini baseline; no installer or filter changes."
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
    /usr/bin/python3 -I -S -B "$task_dir/mini_tcp_diagnostic.py" --run "$task_dir"
