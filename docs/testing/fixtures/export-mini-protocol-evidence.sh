#!/bin/bash
# Exact completed-run evidence only. No installer, service changes or PF calls.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077
if [ "$(/usr/bin/id -u)" -ne 0 ] || [ "$#" -ne 0 ]; then
    echo "Run with sudo and no arguments on the Mini." >&2
    exit 1
fi
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
runtime_root=/Library/SquirrelOps/sensor/python
runtime="$runtime_root/bin/python3.12"
for path in /Library /Library/SquirrelOps /Library/SquirrelOps/sensor "$runtime_root" "$runtime_root/bin" "$runtime"; do
    if [ -L "$path" ] || [ "$(/usr/bin/stat -f %u "$path")" != 0 ]; then
        echo "Untrusted runtime path. No export attempted." >&2
        exit 1
    fi
    mode="$(/usr/bin/stat -f %OLp "$path")"
    if (( (8#$mode & 0022) != 0 )); then
        echo "Writable runtime path. No export attempted." >&2
        exit 1
    fi
done
runtime_sha="$(/usr/bin/shasum -a 256 "$runtime" | /usr/bin/awk '{print $1}')"
if [ "$runtime_sha" != d2555cd22a33506826f9eb069bb13fb0cc41303c7da41da5b761967d616f4147 ]; then
    echo "Installed runtime checksum changed. No export attempted." >&2
    exit 1
fi
/usr/bin/codesign --verify --strict "$runtime"
task_dir="$(/usr/bin/mktemp -d /private/var/root/squirrelops-protocol-export.XXXXXXXX)"
for name in mini_protocol_evidence_export.py mini_readonly_diagnostic_export.py; do
    source_file="$source_dir/$name"
    if [ ! -f "$source_file" ] || [ -L "$source_file" ]; then
        echo "Missing or linked export input." >&2
        exit 1
    fi
    /usr/bin/install -o root -g wheel -m 600 "$source_file" "$task_dir/$name"
    case "$name" in
        mini_protocol_evidence_export.py) expected=9d436c96a4e32cbe18197ecb85bf2f3f1efe6d2491e06e236673a1017cc809eb ;;
        mini_readonly_diagnostic_export.py) expected=ff85896f538b1ff5410d06a06b2129d9035dfe6edb9a51cfdb88b4026bab0380 ;;
    esac
    actual="$(/usr/bin/shasum -a 256 "$task_dir/$name" | /usr/bin/awk '{print $1}')"
    if [ "$actual" != "$expected" ]; then
        echo "Export input checksum changed. No evidence read attempted." >&2
        exit 1
    fi
done
echo "Reading only the completed October 1 packet/PF evidence. No installer, service or filter changes."
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
    "$runtime" -I -B "$task_dir/mini_protocol_evidence_export.py"
