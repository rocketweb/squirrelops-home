#!/bin/bash
# Fixed-session evidence reads only. No installation, restart or filter actions.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077
if [ "$(/usr/bin/id -u)" -ne 0 ] || [ "$#" -ne 0 ]; then
    echo "Run with sudo and no arguments on the mini." >&2
    exit 1
fi
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
runtime_root=/Library/SquirrelOps/sensor/python
runtime="$runtime_root/bin/python3.12"
for path in /Library /Library/SquirrelOps /Library/SquirrelOps/sensor "$runtime_root" "$runtime_root/bin" "$runtime"; do
    if [ -L "$path" ] || [ "$(/usr/bin/stat -f %u "$path")" != 0 ]; then
        echo "Untrusted installed runtime path. No export attempted." >&2
        exit 1
    fi
    mode="$(/usr/bin/stat -f %OLp "$path")"
    if (( (8#$mode & 0022) != 0 )); then
        echo "Writable installed runtime path. No export attempted." >&2
        exit 1
    fi
done
runtime_sha="$(/usr/bin/shasum -a 256 "$runtime" | /usr/bin/awk '{print $1}')"
if [ "$runtime_sha" != d2555cd22a33506826f9eb069bb13fb0cc41303c7da41da5b761967d616f4147 ]; then
    echo "Installed runtime checksum changed. No export attempted." >&2
    exit 1
fi
/usr/bin/codesign --verify --strict "$runtime"
source_file="$source_dir/mini_readonly_diagnostic_export.py"
if [ ! -f "$source_file" ] || [ -L "$source_file" ]; then
    echo "Missing or linked diagnostic input." >&2
    exit 1
fi
task_dir="$(/usr/bin/mktemp -d /private/var/root/squirrelops-readonly-export.XXXXXXXX)"
/usr/bin/install -o root -g wheel -m 600 "$source_file" "$task_dir/export.py"
export_sha="$(/usr/bin/shasum -a 256 "$task_dir/export.py" | /usr/bin/awk '{print $1}')"
if [ "$export_sha" != ff85896f538b1ff5410d06a06b2129d9035dfe6edb9a51cfdb88b4026bab0380 ]; then
    echo "Diagnostic checksum changed. No export attempted." >&2
    exit 1
fi
echo "Reading retained packet metadata, selected sensor events and one minute of traffic history."
echo "No installer, service, database, filter or network-probe changes."
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
    "$runtime" -I -B "$task_dir/export.py"
