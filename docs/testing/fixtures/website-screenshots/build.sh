#!/bin/bash
# Build only an offline screenshot app. Never starts the installed app or sensor.
set -euo pipefail
fixture_dir="$(cd "$(dirname "$0")" && pwd)"
repo_dir="$(cd "$fixture_dir/../../../.." && pwd)"
capture_dir="$(mktemp -d /private/tmp/squirrelops-website-screens.XXXXXXXX)"
mkdir -p "$capture_dir/Sources/SquirrelOpsHome" "$capture_dir/Sources/SquirrelOpsLocalEnrollment"
/usr/bin/rsync -a --exclude App.swift "$repo_dir/app/Sources/SquirrelOpsHome/" "$capture_dir/Sources/SquirrelOpsHome/"
/usr/bin/rsync -a "$repo_dir/app/Sources/SquirrelOpsLocalEnrollment/" "$capture_dir/Sources/SquirrelOpsLocalEnrollment/"
cp "$fixture_dir/Package.swift" "$capture_dir/Package.swift"
cp "$fixture_dir/CaptureApp.swift" "$capture_dir/Sources/SquirrelOpsHome/CaptureApp.swift"
export DEVELOPER_DIR=/Library/Developer/CommandLineTools
export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk
swift build --package-path "$capture_dir" --sdk /Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk
binary_dir="$(swift build --package-path "$capture_dir" --sdk /Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk --show-bin-path)"
bundle="$capture_dir/SquirrelOps Synthetic Screenshots.app"
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
cp "$binary_dir/SquirrelOpsHome" "$bundle/Contents/MacOS/SquirrelOpsScreenshots"
for resource in "$binary_dir"/SquirrelOpsHome_SquirrelOpsHome.bundle; do
    cp -R "$resource" "$bundle/Contents/Resources/"
done
cp "$fixture_dir/Info.plist" "$bundle/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $(tr -d '[:space:]' < "$repo_dir/APP_VERSION")" "$bundle/Contents/Info.plist"
/usr/bin/codesign --force --sign - "$bundle"
printf 'Capture app: %s\nOutput directory: %s\n' "$bundle" "$capture_dir/screenshots"
"$bundle/Contents/MacOS/SquirrelOpsScreenshots" "$capture_dir/screenshots"
