#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
if [ "$#" -eq 0 ]; then
    exec /usr/bin/python3 -I -S -B "$source_dir/edge_client.py"
fi
if [ "$(id -u)" -ne 0 ] || [ "$#" -ne 1 ] || [ "$1" != "--run" ]; then
    echo "Only the approved root --run invocation is supported." >&2
    exit 1
fi
task_dir="$(mktemp -d /root/squirrelops-edge-input.XXXXXXXX)"
for name in edge_client.py edge_guard.py client.py; do
    if [ -L "$source_dir/$name" ] || [ ! -f "$source_dir/$name" ]; then
        echo "Missing or linked client input." >&2
        exit 1
    fi
    install -o root -g root -m 600 "$source_dir/$name" "$task_dir/$name"
    case "$name" in
        edge_client.py) expected='@CLIENT_SHA@' ;;
        edge_guard.py) expected='@GUARD_SHA@' ;;
        client.py) expected='@BASE_CLIENT_SHA@' ;;
    esac
    actual="$(sha256sum "$task_dir/$name" | awk '{print $1}')"
    if [ "$actual" != "$expected" ]; then
        echo "Pinned client input mismatch; no client or filter changes started." >&2
        exit 1
    fi
done
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
    /usr/bin/python3 -I -S -B -u "$task_dir/edge_client.py" --run
