"""Process-boundary tests for the signed macOS deception guest runtime."""

import asyncio
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from squirrelops_home_sensor.decoys.deep.guest_runtime import (
    GuestConnectionTelemetry,
    GuestRuntimeController,
    GuestRuntimeError,
)
from squirrelops_home_sensor.decoys.deep.persona import build_studio_mini_persona


def _write_bundle(root: Path) -> None:
    root.mkdir(mode=0o700)
    kernel = b"test-linux-kernel"
    initramfs = b"test-memory-only-rootfs"
    (root / "vmlinuz").write_bytes(kernel)
    (root / "studio-mini.initramfs").write_bytes(initramfs)
    manifest = {
        "schema_version": 1,
        "persona_id": "studio-mini-v1",
        "boot": {
            "kernel": {
                "path": "vmlinuz",
                "sha256": hashlib.sha256(kernel).hexdigest(),
            },
            "initial_ramdisk": {
                "path": "studio-mini.initramfs",
                "sha256": hashlib.sha256(initramfs).hexdigest(),
            },
            "command_line": "console=hvc0 rdinit=/sbin/init",
        },
        "resources": {
            "cpu_count": 2,
            "memory_bytes": 1073741824,
            "max_connections": 16,
        },
        "containment": {
            "network_devices": 0,
            "host_shares": [],
            "clipboard": False,
            "egress": "none",
            "root_filesystem": "memory-only",
        },
        "services": [
            {"name": "ssh", "advertised_port": 22, "guest_vsock_port": 10022},
            {"name": "smb", "advertised_port": 445, "guest_vsock_port": 10445},
        ],
    }
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def _write_runtime(path: Path, ready_line: str, *, keep_running: bool = True) -> None:
    tail = "while true; do sleep 1; done" if keep_running else "exit 0"
    path.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' '{ready_line}'\n"
        f"{tail}\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _persona():
    return build_studio_mini_persona(
        b"r" * 32,
        datetime(2026, 8, 31, 16, 0, tzinfo=UTC),
    )


@pytest.mark.asyncio
async def test_runtime_reports_only_ssh_and_smb_backend_ports(tmp_path: Path) -> None:
    bundle = tmp_path / "guest"
    state = tmp_path / "state"
    runtime = tmp_path / "SquirrelOpsDeceptionGuest"
    _write_bundle(bundle)
    _write_runtime(
        runtime,
        '{"status":"ready","persona_id":"studio-mini-v1",'
        '"services":{"22":49122,"445":49445}}',
    )
    controller = GuestRuntimeController(
        executable=runtime,
        bundle_root=bundle,
        state_dir=state,
        bind_address="127.0.0.1",
        trusted_uids={os.getuid()},
        persona=_persona(),
    )

    ports = await controller.start()
    try:
        assert ports == {22: 49122, 445: 49445}
        assert controller.is_running is True
    finally:
        await controller.stop()

    assert controller.is_running is False


@pytest.mark.asyncio
async def test_runtime_executable_must_not_be_symlinked(tmp_path: Path) -> None:
    bundle = tmp_path / "guest"
    state = tmp_path / "state"
    real_runtime = tmp_path / "real-runtime"
    runtime = tmp_path / "SquirrelOpsDeceptionGuest"
    _write_bundle(bundle)
    _write_runtime(real_runtime, '{"status":"ready"}')
    runtime.symlink_to(real_runtime)
    controller = GuestRuntimeController(
        executable=runtime,
        bundle_root=bundle,
        state_dir=state,
        bind_address="127.0.0.1",
        trusted_uids={os.getuid()},
        persona=_persona(),
    )

    with pytest.raises(GuestRuntimeError, match="regular file"):
        await controller.start()


@pytest.mark.asyncio
async def test_runtime_executable_must_not_be_group_writable(tmp_path: Path) -> None:
    bundle = tmp_path / "guest"
    state = tmp_path / "state"
    runtime = tmp_path / "SquirrelOpsDeceptionGuest"
    _write_bundle(bundle)
    _write_runtime(runtime, '{"status":"ready"}')
    runtime.chmod(0o775)
    controller = GuestRuntimeController(
        executable=runtime,
        bundle_root=bundle,
        state_dir=state,
        bind_address="127.0.0.1",
        trusted_uids={os.getuid()},
        persona=_persona(),
    )

    with pytest.raises(GuestRuntimeError, match="writable"):
        await controller.start()


@pytest.mark.asyncio
async def test_runtime_cannot_publish_unreviewed_port(tmp_path: Path) -> None:
    bundle = tmp_path / "guest"
    state = tmp_path / "state"
    runtime = tmp_path / "SquirrelOpsDeceptionGuest"
    _write_bundle(bundle)
    _write_runtime(
        runtime,
        '{"status":"ready","persona_id":"studio-mini-v1",'
        '"services":{"22":49122,"445":49445,"9001":49901}}',
    )
    controller = GuestRuntimeController(
        executable=runtime,
        bundle_root=bundle,
        state_dir=state,
        bind_address="127.0.0.1",
        trusted_uids={os.getuid()},
        persona=_persona(),
    )

    with pytest.raises(GuestRuntimeError, match="service set"):
        await controller.start()
    assert controller.is_running is False


@pytest.mark.asyncio
async def test_runtime_exit_before_readiness_fails_closed(tmp_path: Path) -> None:
    bundle = tmp_path / "guest"
    state = tmp_path / "state"
    runtime = tmp_path / "SquirrelOpsDeceptionGuest"
    _write_bundle(bundle)
    _write_runtime(runtime, '{"status":"starting"}', keep_running=False)
    controller = GuestRuntimeController(
        executable=runtime,
        bundle_root=bundle,
        state_dir=state,
        bind_address="127.0.0.1",
        trusted_uids={os.getuid()},
        persona=_persona(),
    )

    with pytest.raises(GuestRuntimeError, match="ready"):
        await controller.start()
    assert controller.is_running is False


@pytest.mark.asyncio
async def test_runtime_drains_and_validates_connection_telemetry(tmp_path: Path) -> None:
    bundle = tmp_path / "guest"
    state = tmp_path / "state"
    runtime = tmp_path / "SquirrelOpsDeceptionGuest"
    _write_bundle(bundle)
    runtime.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' '{\"status\":\"ready\",\"persona_id\":\"studio-mini-v1\","
        "\"services\":{\"22\":49122,\"445\":49445}}'\n"
        "printf '%s\\n' '{\"event\":\"connection\",\"source_ip\":\"192.0.2.44\","
        "\"source_port\":53012,\"dest_port\":445,\"protocol\":\"tcp\","
        "\"interaction_type\":\"smb.connection\","
        "\"timestamp\":\"2026-08-31T16:01:02Z\"}'\n"
        "while true; do sleep 1; done\n",
        encoding="utf-8",
    )
    runtime.chmod(0o755)
    received: list[GuestConnectionTelemetry] = []
    observed = asyncio.Event()

    def capture(event: GuestConnectionTelemetry) -> None:
        received.append(event)
        observed.set()

    controller = GuestRuntimeController(
        executable=runtime,
        bundle_root=bundle,
        state_dir=state,
        bind_address="127.0.0.1",
        trusted_uids={os.getuid()},
        persona=_persona(),
        on_connection=capture,
    )

    await controller.start()
    try:
        await asyncio.wait_for(observed.wait(), timeout=2)
        assert received == [
            GuestConnectionTelemetry(
                source_ip="192.0.2.44",
                source_port=53012,
                dest_port=445,
                protocol="tcp",
                interaction_type="smb.connection",
                timestamp=datetime(2026, 8, 31, 16, 1, 2, tzinfo=UTC),
            )
        ]
    finally:
        await controller.stop()


@pytest.mark.asyncio
async def test_runtime_reports_an_unexpected_exit_and_clears_backend_ports(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "guest"
    state = tmp_path / "state"
    runtime = tmp_path / "SquirrelOpsDeceptionGuest"
    _write_bundle(bundle)
    runtime.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' '{\"status\":\"ready\",\"persona_id\":\"studio-mini-v1\","
        "\"services\":{\"22\":49122,\"445\":49445}}'\n"
        "sleep 0.1\n"
        "exit 23\n",
        encoding="utf-8",
    )
    runtime.chmod(0o755)
    exit_codes: list[int] = []
    exited = asyncio.Event()

    def capture_exit(returncode: int) -> None:
        exit_codes.append(returncode)
        exited.set()

    controller = GuestRuntimeController(
        executable=runtime,
        bundle_root=bundle,
        state_dir=state,
        bind_address="127.0.0.1",
        trusted_uids={os.getuid()},
        persona=_persona(),
        on_exit=capture_exit,
    )

    assert await controller.start() == {22: 49122, 445: 49445}
    await asyncio.wait_for(exited.wait(), timeout=2)

    assert exit_codes == [23]
    assert controller.is_running is False
    assert controller.backend_ports == {}
    await controller.stop()


@pytest.mark.asyncio
async def test_requested_runtime_stop_does_not_report_a_crash(tmp_path: Path) -> None:
    bundle = tmp_path / "guest"
    state = tmp_path / "state"
    runtime = tmp_path / "SquirrelOpsDeceptionGuest"
    _write_bundle(bundle)
    _write_runtime(
        runtime,
        '{"status":"ready","persona_id":"studio-mini-v1",'
        '"services":{"22":49122,"445":49445}}',
    )
    exit_codes: list[int] = []
    controller = GuestRuntimeController(
        executable=runtime,
        bundle_root=bundle,
        state_dir=state,
        bind_address="127.0.0.1",
        trusted_uids={os.getuid()},
        persona=_persona(),
        on_exit=exit_codes.append,
    )

    await controller.start()
    await controller.stop()
    await asyncio.sleep(0)

    assert exit_codes == []
