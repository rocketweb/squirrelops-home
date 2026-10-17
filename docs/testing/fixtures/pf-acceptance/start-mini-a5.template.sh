#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077
if [ "$(id -u)" -ne 0 ] || [ "$#" -ne 0 ] || [ ! -t 0 ]; then
    echo "Run with sudo, without arguments, in an attended Mini Terminal." >&2
    exit 1
fi
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
for directory in /Library /Library/SquirrelOps /Library/SquirrelOps/acceptance-backups; do
    if [ -L "$directory" ] || [ ! -d "$directory" ] || [ "$(stat -f %u "$directory")" -ne 0 ]; then
        echo "Unsafe durable backup parent; no test started." >&2
        exit 1
    fi
    mode="$(stat -f %OLp "$directory")"
    if (( (8#$mode & 8#022) != 0 )); then
        echo "Writable durable backup parent; no test started." >&2
        exit 1
    fi
done
task_dir="$(mktemp -d /Library/SquirrelOps/acceptance-backups/mini-a5-20261002.XXXXXXXX)"
for name in SquirrelOpsPFProbe runner.py client.py README.md source-sha256.txt SHA256SUMS; do
    if [ -L "$source_dir/$name" ] || [ ! -f "$source_dir/$name" ]; then
        echo "Missing or linked test input; no test started." >&2
        exit 1
    fi
    install -o root -g wheel -m 600 "$source_dir/$name" "$task_dir/$name"
done
manifest_sha="$(shasum -a 256 "$task_dir/SHA256SUMS" | awk '{print $1}')"
if [ "$manifest_sha" != "@MANIFEST_SHA@" ]; then
    echo "Pinned input manifest mismatch; no test started." >&2
    exit 1
fi
(cd "$task_dir" && shasum -a 256 -c SHA256SUMS)
chmod 700 "$task_dir/SquirrelOpsPFProbe"
echo "Pinned A5 inputs verified. Checking the stopped Mini before network changes."
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
    /usr/bin/python3 -I -S -B "$task_dir/runner.py" --run "$task_dir"
