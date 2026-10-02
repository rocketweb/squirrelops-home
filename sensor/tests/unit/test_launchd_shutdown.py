"""Packaging budget and opt-in, disposable launchd shutdown regression."""

from __future__ import annotations

import os
import plistlib
import subprocess
import sys
import textwrap
import time
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
TEMPLATE = ROOT / "sensor/resources/com.squirrelops.sensor.plist"
SCRIPTS = (
    "scripts/pkg/preinstall",
    "scripts/pkg/app-scripts/preinstall",
    "scripts/pkg/uninstall.sh",
)


def test_launchd_has_finite_budget_for_ordered_runtime_cleanup():
    template = plistlib.loads(TEMPLATE.read_bytes())
    # mDNS goodbye (~3s), scan drain (10s), scout drain (10s), guest (8s),
    # plus bounded helper/relay and remaining resource cleanup need headroom.
    assert template.get("ExitTimeOut") == 60


@pytest.mark.parametrize("script", SCRIPTS)
@pytest.mark.parametrize("label,stop_after", [
    ("com.squirrelops.sensor", 15),
    ("com.squirrelops.sensor", 65),
    ("com.squirrelops.helper", 3),
])
def test_package_stop_poll_outlives_sensor_exit_budget(tmp_path, script, label, stop_after):
    source = (ROOT / script).read_text()
    start = source.index("stop_service_and_verify() {")
    end = source.index("\n}\n", start) + 3
    function = source[start:end]
    # Execute the actual shell function with a virtual clock. No launchctl or
    # installed path can be reached from this fixture.
    program = f"""
{function}
clock=0
info() {{ :; }}
warn() {{ :; }}
sleep() {{ clock=$((clock + 1)); }}
launchctl() {{ [ "$1" = bootout ]; }}
service_is_loaded() {{ [ "$clock" -lt {stop_after} ]; }}
stop_service_and_verify {label} fixture
"""
    result = subprocess.run(["/bin/bash", "-c", program], capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("script", SCRIPTS)
@pytest.mark.parametrize("label,expected_wait", [("com.squirrelops.sensor", 70), ("com.squirrelops.helper", 10)])
def test_package_stop_failure_remains_bounded(script, label, expected_wait):
    source = (ROOT / script).read_text()
    start = source.index("stop_service_and_verify() {")
    end = source.index("\n}\n", start) + 3
    program = f"""
{source[start:end]}
clock=0
info() {{ :; }}
warn() {{ :; }}
sleep() {{ clock=$((clock + 1)); }}
launchctl() {{ [ "$1" = bootout ]; }}
service_is_loaded() {{ return 0; }}
stop_service_and_verify {label} fixture
result=$?
[ "$result" = 1 ] && [ "$clock" = {expected_wait} ]
"""
    result = subprocess.run(["/bin/bash", "-c", program], capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(
    sys.platform != "darwin" or os.environ.get("SQUIRRELOPS_TEST_LAUNCHD") != "1",
    reason="Explicit opt-in: private user-domain launchd job, no installed services",
)
def test_real_launchd_allows_cleanup_after_slow_scan(tmp_path):
    """Exercise the actual signal boundary and scan drain under launchd.

    The scan waits for its real 10s drain timeout; mDNS/guest/DB are fakes.
    No network, helper, VM, installed files, or administrative privileges.
    """
    assert os.geteuid() != 0, "Use the console user's disposable launchd domain"
    program = tmp_path / "shutdown_probe.py"
    evidence = tmp_path / "events.txt"
    program.write_text(textwrap.dedent("""
        import asyncio
        import sys
        from pathlib import Path
        from types import SimpleNamespace
        import squirrelops_home_sensor.__main__ as entry

        output = Path(sys.argv[1])
        def record(value):
            with output.open('a') as stream:
                stream.write(value + '\\n')
        async def mdns_stop():
            record('MDNS_STOPPING')
            await asyncio.sleep(3)
        async def guest_stop():
            record('GUEST_STOPPED')
        async def database_close():
            record('DATABASE_CLOSED')
        async def serve(server, sockets=None):
            record('READY')
            while not server.should_exit:
                await asyncio.sleep(0.01)
        async def main():
            runtime = entry._RuntimeResources({'sensor': {'data_dir': str(output.parent)}})
            runtime.mdns = SimpleNamespace(stop=mdns_stop)
            runtime.mdns_start_attempted = True
            scan = entry._ScanLoopWrapper(SimpleNamespace())
            scan._task = asyncio.create_task(asyncio.Event().wait())
            runtime.scan_loop = scan
            runtime.scan_start_attempted = True
            runtime.deep_orchestrator = SimpleNamespace(stop_all=guest_stop)
            runtime.deep_start_attempted = True
            runtime.db = SimpleNamespace(close=database_close)
            # Replace only the HTTP serving body, not signal capture or cleanup.
            entry.uvicorn.Server._serve = serve
            server = entry._RuntimeManagedServer(entry.uvicorn.Config('unused'), runtime=runtime)
            await server.serve()
        asyncio.run(main())
    """))
    label = "com.squirrelops.test.shutdown." + uuid.uuid4().hex
    target = f"gui/{os.getuid()}/{label}"
    template = plistlib.loads(TEMPLATE.read_bytes())
    job = {
        "Label": label,
        "ProgramArguments": [os.environ.get("SQUIRRELOPS_TEST_SENSOR_PYTHON", sys.executable),
                             "-I", "-B", str(program), str(evidence)],
        "RunAtLoad": True,
        "KeepAlive": False,
        "StandardOutPath": str(tmp_path / "stdout.log"),
        "StandardErrorPath": str(tmp_path / "stderr.log"),
    }
    if "ExitTimeOut" in template:
        job["ExitTimeOut"] = template["ExitTimeOut"]
    plist = tmp_path / "probe.plist"
    plist.write_bytes(plistlib.dumps(job))
    loaded = False
    try:
        subprocess.run(["/bin/launchctl", "bootstrap", f"gui/{os.getuid()}", str(plist)],
                       check=True, capture_output=True, text=True, timeout=10)
        loaded = True
        deadline = time.monotonic() + 20
        while not evidence.exists() or 'READY' not in evidence.read_text():
            assert time.monotonic() < deadline, (tmp_path / "stderr.log").read_text()
            time.sleep(0.1)
        subprocess.run(["/bin/launchctl", "bootout", target], check=True,
                       capture_output=True, text=True, timeout=75)
        deadline = time.monotonic() + 75
        while subprocess.run(["/bin/launchctl", "print", target], capture_output=True, timeout=5).returncode == 0:
            assert time.monotonic() < deadline, "Disposable job failed to exit"
            time.sleep(0.1)
        loaded = False
        events = evidence.read_text().splitlines()
        assert events == ['READY', 'MDNS_STOPPING', 'GUEST_STOPPED', 'DATABASE_CLOSED'], (
            events, (tmp_path / "stderr.log").read_text(),
        )
    finally:
        if loaded:
            subprocess.run(["/bin/launchctl", "bootout", target], capture_output=True, timeout=75)
