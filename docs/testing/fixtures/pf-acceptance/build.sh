#!/bin/bash
# Builds an offline, standalone probe from unchanged production helper sources.
set -euo pipefail
fixture_dir="$(cd "$(dirname "$0")" && pwd -P)"
repo_dir="$(cd "$fixture_dir/../../../.." && pwd -P)"
build_dir="$(mktemp -d /private/tmp/squirrelops-a5-build.XXXXXXXX)"
mkdir -p "$build_dir/Sources/SquirrelOpsPFProbe" "$build_dir/Sources/SquirrelOpsLocalEnrollment" "$build_dir/stage"
rsync -a --exclude main.swift "$repo_dir/app/Sources/SquirrelOpsHelper/" "$build_dir/Sources/SquirrelOpsPFProbe/"
rsync -a "$repo_dir/app/Sources/SquirrelOpsLocalEnrollment/" "$build_dir/Sources/SquirrelOpsLocalEnrollment/"
cp "$fixture_dir/main.swift" "$build_dir/Sources/SquirrelOpsPFProbe/main.swift"
cp "$fixture_dir/Package.swift" "$build_dir/Package.swift"
export DEVELOPER_DIR=/Library/Developer/CommandLineTools
export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk
swift build --package-path "$build_dir" --sdk "$SDKROOT" -c release
binary_dir="$(swift build --package-path "$build_dir" --sdk "$SDKROOT" -c release --show-bin-path)"
cp "$binary_dir/SquirrelOpsPFProbe" "$build_dir/stage/SquirrelOpsPFProbe"
codesign --force --sign - --identifier com.squirrelops.test.pf-acceptance "$build_dir/stage/SquirrelOpsPFProbe"
cp "$fixture_dir/runner.py" "$fixture_dir/client.py" "$fixture_dir/README.md" "$build_dir/stage/"
# Record both the canonical helper input and the independently built harness.
(cd "$repo_dir" && /usr/bin/shasum -a 256 app/Sources/SquirrelOpsHelper/*.swift app/Sources/SquirrelOpsLocalEnrollment/*.swift) > "$build_dir/stage/source-sha256.txt"
(cd "$build_dir/stage" && /usr/bin/shasum -a 256 SquirrelOpsPFProbe runner.py client.py README.md source-sha256.txt) > "$build_dir/stage/SHA256SUMS"
manifest_sha="$(/usr/bin/shasum -a 256 "$build_dir/stage/SHA256SUMS" | /usr/bin/awk '{print $1}')"
/usr/bin/sed "s/@MANIFEST_SHA@/$manifest_sha/" "$fixture_dir/start-mini-a5.template.sh" > "$build_dir/stage/start-mini-a5.sh"
chmod 700 "$build_dir/stage/start-mini-a5.sh"
"$build_dir/stage/SquirrelOpsPFProbe"
printf 'Staging bundle: %s\n' "$build_dir/stage"
