"""Exercise app/package path discovery without compiling or creating an installer."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def builder(tmp_path):
    root = tmp_path / "checkout with spaces"
    app = root / "app"
    app.mkdir(parents=True)
    shutil.copy2(REPO_ROOT / "app/build-app.sh", app / "build-app.sh")
    for name in ("APP_VERSION", "VERSION"):
        (root / name).write_text("2.1.0\n")
    commands = root / "commands"
    commands.mkdir()
    swift = commands / "swift"
    swift.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, pathlib, sys\n"
        "with open(os.environ['CALL_LOG'], 'a') as log:\n"
        "    log.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "if '--show-bin-path' in sys.argv:\n"
        "    print(os.environ['BIN_PATH'])\n"
        "    sys.exit(int(os.environ.get('QUERY_EXIT', '0')))\n"
        "sys.exit(int(os.environ.get('BUILD_EXIT', '0')))\n"
    )
    swift.chmod(0o755)
    signer = commands / "codesign"
    signer.write_text("#!/bin/sh\nexit 0\n")
    signer.chmod(0o755)
    products = app / ".build/out/Products/Debug"
    products.mkdir(parents=True)
    for name in ("SquirrelOpsHome", "SquirrelOpsHelper", "SquirrelOpsDeceptionGuest"):
        binary = products / name
        binary.write_text(f"fresh {name}\n")
        binary.chmod(0o755)
    resources = products / "SquirrelOpsHome_SquirrelOpsHome.bundle"
    resources.mkdir()
    (resources / "AppIcon.icns").write_text("fresh icon\n")
    env = {
        **os.environ,
        "PATH": f"{commands}:{os.environ['PATH']}",
        "CALL_LOG": str(root / "calls.jsonl"),
        "BIN_PATH": str(products),
        "BUILD_CONFIG": "debug",
        "BUILD_ARCH": "arm64",
        "SQUIRRELOPS_GUEST_BUNDLE": str(root / "absent-guest"),
    }
    for key in ("SQUIRRELOPS_SWIFT_SDK", "SQUIRRELOPS_SWIFT_SCRATCH_PATH",
                "SQUIRRELOPS_APP_VERSION"):
        env.pop(key, None)
    return app, products, env


def run_builder(builder, *args):
    app, _, env = builder
    return subprocess.run(
        ["/bin/bash", str(app / "build-app.sh"), *args],
        cwd=app.parent, env=env, text=True, capture_output=True,
    )


def test_bundle_uses_swift_reported_products_not_stale_legacy_output(builder):
    app, products, _ = builder
    stale = app / ".build/arm64-apple-macosx/debug/SquirrelOpsHome.app"
    stale.mkdir(parents=True)
    (stale / "keep.txt").write_text("previous artifact")
    result = run_builder(builder)
    assert result.returncode == 0, result.stdout + result.stderr
    bundle = products / "SquirrelOpsHome.app/Contents"
    assert (bundle / "MacOS/SquirrelOpsHome").read_text() == "fresh SquirrelOpsHome\n"
    assert (bundle / "Library/LaunchServices/com.squirrelops.helper").is_file()
    assert (bundle / "Library/Helpers/com.squirrelops.deception-guest").is_file()
    assert (bundle / "Resources/AppIcon.icns").read_text() == "fresh icon\n"
    assert (stale / "keep.txt").read_text() == "previous artifact"


@pytest.mark.parametrize("layout", ["out/Products/Release", "x86_64-apple-macosx/release"])
def test_print_mode_only_queries_with_matching_configuration_arch_sdk_and_scratch(builder, layout):
    app, _, env = builder
    scratch = app.parent / "separate build"
    products = scratch / layout
    products.mkdir(parents=True)
    sdk = app.parent / "Selected SDK.sdk"
    sdk.mkdir()
    env.update(BUILD_CONFIG="release", BUILD_ARCH="x86_64", BIN_PATH=str(products),
               SQUIRRELOPS_SWIFT_SDK=str(sdk), SQUIRRELOPS_SWIFT_SCRATCH_PATH=str(scratch))
    result = run_builder(builder, "--print-bundle-path")
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == str(products / "SquirrelOpsHome.app")
    calls = [json.loads(line) for line in Path(env["CALL_LOG"]).read_text().splitlines()]
    assert len(calls) == 1 and "--show-bin-path" in calls[0]
    assert calls[0][calls[0].index("--sdk") + 1] == str(sdk)
    assert calls[0][calls[0].index("--scratch-path") + 1] == str(scratch)
    assert calls[0][calls[0].index("-c") + 1] == "release"
    if os.uname().machine != "x86_64":
        assert calls[0][calls[0].index("--arch") + 1] == "x86_64"


def test_build_and_query_use_identical_flags(builder):
    app, _, env = builder
    sdk = app.parent / "SDK with spaces.sdk"
    sdk.mkdir()
    env["SQUIRRELOPS_SWIFT_SDK"] = str(sdk)
    result = run_builder(builder)
    assert result.returncode == 0, result.stdout + result.stderr
    calls = [json.loads(line) for line in Path(env["CALL_LOG"]).read_text().splitlines()]
    assert len(calls) == 2
    build = next(call for call in calls if "--show-bin-path" not in call)
    query = next(call for call in calls if "--show-bin-path" in call)
    assert [arg for arg in query if arg != "--show-bin-path"] == build


@pytest.mark.parametrize("invalid", ["", "/", "relative/path", "{app}/.build/../outside",
                                    "{app}/.build/out\n/another/path", "{app}/unrelated"])
def test_invalid_reported_path_fails_without_replacing_existing_bundle(builder, invalid):
    app, products, env = builder
    bundle = products / "SquirrelOpsHome.app"
    bundle.mkdir()
    marker = bundle / "keep.txt"
    marker.write_text("retain me")
    env["BIN_PATH"] = invalid.format(app=app)
    result = run_builder(builder, "--print-bundle-path")
    assert result.returncode != 0
    assert "build output" in result.stderr.lower()
    assert marker.read_text() == "retain me"


@pytest.mark.parametrize("variable", ["QUERY_EXIT", "BUILD_EXIT"])
def test_failed_swift_does_not_replace_bundle(builder, variable):
    _, products, env = builder
    bundle = products / "SquirrelOpsHome.app"
    bundle.mkdir()
    (bundle / "keep.txt").write_text("retain me")
    env[variable] = "7"
    result = run_builder(builder)
    assert result.returncode != 0
    assert (bundle / "keep.txt").read_text() == "retain me"


def test_package_locates_bundle_through_the_same_builder(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    bundle = app / "new toolchain output/SquirrelOpsHome.app"
    bundle.mkdir(parents=True)
    script = app / "build-app.sh"
    script.write_text(
        '#!/bin/bash\nset -eu\n'
        'test "$BUILD_CONFIG" = release\ntest "$BUILD_ARCH" = arm64\n'
        'if [ "${1:-}" = --print-bundle-path ]; then\n'
        '    printf "%s\\n" "$EXPECTED_BUNDLE"\nfi\n'
    )
    package = (REPO_ROOT / "scripts/build-pkg.sh").read_text()
    start = package.index('info "Building SquirrelOps Home.app')
    end = package.index('APP_EXECUTABLE=', start)
    command = ('info() { :; }; error() { echo "$*" >&2; exit 1; };\n'
               + package[start:end] + '\ntest "$APP_BUNDLE" = "$EXPECTED_BUNDLE"')
    result = subprocess.run(
        ["/bin/bash", "-eu", "-c", command], text=True, capture_output=True,
        env={**os.environ, "REPO_ROOT": str(tmp_path), "BUILD_ARCH": "arm64",
             "EXPECTED_BUNDLE": str(bundle)},
    )
    assert result.returncode == 0, result.stdout + result.stderr
