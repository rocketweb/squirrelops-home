#!/bin/bash
# One attended, approved Mac mini session. No password is read by this script.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077

if [ "$(/usr/bin/id -u)" -ne 0 ] || [ "$#" -gt 1 ]; then
    echo "Run with sudo in the mini's Terminal; only --resume-failed-install is supported." >&2
    exit 1
fi
resume_failed_install=0
if [ "$#" -eq 1 ]; then
    if [ "$1" != "--resume-failed-install" ]; then
        echo "Unsupported argument. No setup attempted." >&2
        exit 1
    fi
    resume_failed_install=1
fi

prepare_run_args() {
    # A nonempty array is required by macOS Bash 3.2 with set -u.
    run_args=(--run "$task_dir")
    if [ "$resume_failed_install" -eq 1 ]; then
        run_args+=(--resume-failed-install)
    fi
}
if [ ! -t 0 ]; then
    echo "This requires an attended Terminal session on the mini." >&2
    exit 1
fi

source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
task_dir="$(/usr/bin/mktemp -d /private/var/root/squirrelops-mini-acceptance.XXXXXXXX)"
for name in candidate.pkg mini-a5-config.yaml mini_acceptance.py; do
    if [ ! -f "$source_dir/$name" ] || [ -L "$source_dir/$name" ]; then
        echo "Missing or linked setup input: $name" >&2
        exit 1
    fi
    /usr/bin/install -o root -g wheel -m 600 "$source_dir/$name" "$task_dir/$name"
done

verify_digest() {
    local name="$1" expected="$2" actual
    actual="$(/usr/bin/shasum -a 256 "$task_dir/$name" | /usr/bin/awk '{print $1}')"
    if [ "$actual" != "$expected" ]; then
        echo "Checksum mismatch: $name. No installation attempted." >&2
        exit 1
    fi
}
verify_digest candidate.pkg 3e8c0fc78befad3365fdbff5583d9f85c6b6fe01816b5863edbebeceaa4b8f5f
verify_digest mini-a5-config.yaml 6e210567e3baae3950d91153b44090876ae6978b2a67677b1690aaf5c8f02330
verify_digest mini_acceptance.py 47b6c6df59083230ac63f97f1b32c55fa804f71839d433bfbc9fb952bf7bd40a

echo "Setup inputs verified. Preparing the pinned package's private Python runtime."
/usr/sbin/pkgutil --expand-full "$task_dir/candidate.pkg" "$task_dir/expanded"
runtime="$task_dir/expanded/sensor.pkg/Payload/Library/SquirrelOps/sensor/python/bin/python3"
/usr/bin/codesign --verify --strict "$runtime"
prepare_run_args
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
    "$runtime" -I -B "$task_dir/mini_acceptance.py" "${run_args[@]}"
