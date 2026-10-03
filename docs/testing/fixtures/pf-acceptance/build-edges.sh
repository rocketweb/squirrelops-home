#!/bin/bash
set -euo pipefail
fixture_dir="$(cd "$(dirname "$0")" && pwd -P)"
build_output="$(/bin/bash "$fixture_dir/build.sh")"
printf '%s\n' "$build_output"
stage="$(printf '%s\n' "$build_output" | /usr/bin/awk '/^Staging bundle: / {print $3}')"
case "$stage" in /private/tmp/squirrelops-a5-build.*/stage) ;; *) exit 1 ;; esac
cp "$fixture_dir"/edge_child.py "$fixture_dir"/edge_runner.py "$fixture_dir"/edge_client.py \
   "$fixture_dir"/edge_guard.py "$fixture_dir"/inspect_completed.py "$fixture_dir"/EDGES.md "$stage/"
(cd "$stage" && shasum -a 256 SquirrelOpsPFProbe runner.py client.py edge_child.py edge_runner.py \
    edge_client.py edge_guard.py inspect_completed.py README.md EDGES.md source-sha256.txt) > "$stage/SHA256SUMS"
manifest_sha="$(shasum -a 256 "$stage/SHA256SUMS" | awk '{print $1}')"
sed "s/@MANIFEST_SHA@/$manifest_sha/" "$fixture_dir/start-mini-a5-edges.template.sh" > "$stage/start-mini-a5-edges.sh"
client_sha="$(shasum -a 256 "$stage/edge_client.py" | awk '{print $1}')"
guard_sha="$(shasum -a 256 "$stage/edge_guard.py" | awk '{print $1}')"
base_sha="$(shasum -a 256 "$stage/client.py" | awk '{print $1}')"
sed -e "s/@CLIENT_SHA@/$client_sha/" -e "s/@GUARD_SHA@/$guard_sha/" -e "s/@BASE_CLIENT_SHA@/$base_sha/" \
    "$fixture_dir/run-laptop-a5-edges.template.sh" > "$stage/run-laptop-a5-edges.sh"
chmod 700 "$stage/start-mini-a5-edges.sh" "$stage/run-laptop-a5-edges.sh"
/bin/bash -n "$stage/start-mini-a5-edges.sh"
/bin/bash -n "$stage/run-laptop-a5-edges.sh"
printf 'Edge staging bundle: %s\n' "$stage"
