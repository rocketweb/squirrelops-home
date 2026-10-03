#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077
if [ "$(id -u)" -ne 0 ] || [ "$#" -ne 0 ]; then
    echo "Run with sudo and no arguments on the Mini." >&2
    exit 1
fi
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
if [ -L "$source_dir/inspect_completed.py" ] || [ ! -f "$source_dir/inspect_completed.py" ]; then
    echo "Missing or linked inspection input." >&2
    exit 1
fi
task_dir="$(mktemp -d /private/var/root/squirrelops-a5-inspect.XXXXXXXX)"
install -o root -g wheel -m 600 "$source_dir/inspect_completed.py" "$task_dir/inspect_completed.py"
digest="$(shasum -a 256 "$task_dir/inspect_completed.py" | awk '{print $1}')"
if [ "$digest" != "@INSPECTOR_SHA@" ]; then
    echo "Inspection checksum mismatch; no evidence read attempted." >&2
    exit 1
fi
echo "Reading only the two completed A5 runs. No live commands or network changes."
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
    /usr/bin/python3 -I -S -B "$task_dir/inspect_completed.py" --run
