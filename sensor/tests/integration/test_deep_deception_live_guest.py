"""Opt-in live acceptance for the Virtualization.framework guest artifacts."""

from __future__ import annotations

import asyncio
import os
import shlex
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
import smbclient

from squirrelops_home_sensor.decoys.deep.guest_runtime import (
    GuestConnectionTelemetry,
    GuestRuntimeController,
)
from squirrelops_home_sensor.decoys.deep.persona import build_studio_mini_persona


def _required_path(name: str) -> Path:
    value = os.environ.get(name)
    if not value:
        pytest.skip(f"{name} is required for live guest acceptance")
    return Path(value)


def _ssh_environment(password: str, tmp_path: Path) -> dict[str, str]:
    askpass = tmp_path / "askpass"
    askpass.write_text(
        f"#!/bin/sh\nprintf '%s\\n' {shlex.quote(password)}\n",
        encoding="utf-8",
    )
    askpass.chmod(0o700)
    return {
        "DISPLAY": "squirrelops-live-test",
        "PATH": "/usr/bin:/bin",
        "SSH_ASKPASS": str(askpass),
        "SSH_ASKPASS_REQUIRE": "force",
    }


async def _run_process(
    arguments: Sequence[str],
    *,
    environment: dict[str, str] | None = None,
    stdin: bytes | None = None,
    timeout: float = 15,
) -> tuple[str, str]:
    process = await asyncio.create_subprocess_exec(
        *arguments,
        stdin=asyncio.subprocess.PIPE if stdin is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=environment,
    )
    stdout, stderr = await asyncio.wait_for(
        process.communicate(input=stdin),
        timeout=timeout,
    )
    decoded_stdout = stdout.decode("utf-8", errors="replace")
    decoded_stderr = stderr.decode("utf-8", errors="replace")
    assert process.returncode == 0, decoded_stderr
    return decoded_stdout, decoded_stderr


async def _ssh_command(
    port: int,
    password: str,
    tmp_path: Path,
    command: str,
) -> str:
    environment = _ssh_environment(password, tmp_path)
    process = await asyncio.create_subprocess_exec(
        "/usr/bin/ssh",
        "-F",
        "/dev/null",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "PreferredAuthentications=password",
        "-o",
        "PubkeyAuthentication=no",
        "-o",
        "NumberOfPasswordPrompts=1",
        "-o",
        "ConnectTimeout=5",
        "-p",
        str(port),
        "buildbot@127.0.0.1",
        command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=environment,
    )
    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10)
    assert process.returncode == 0, stderr.decode("utf-8", errors="replace")
    return stdout.decode("utf-8")


async def _sftp_round_trip(port: int, password: str, tmp_path: Path) -> None:
    upload = tmp_path / "sftp-upload.txt"
    download = tmp_path / "sftp-download.txt"
    project_readme = tmp_path / "fieldkit-readme.md"
    upload.write_text("SquirrelOps live SFTP acceptance\n", encoding="utf-8")
    commands = "\n".join(
        (
            f'get /Users/buildbot/Projects/fieldkit-ios/README.md "{project_readme}"',
            f'put "{upload}" /Users/buildbot/Builds/squirrelops-acceptance.txt',
            f'get /Users/buildbot/Builds/squirrelops-acceptance.txt "{download}"',
            "rm /Users/buildbot/Builds/squirrelops-acceptance.txt",
        )
    )
    commands += "\n"
    stdout, stderr = await _run_process(
        (
            "/usr/bin/sftp",
            "-F",
            "/dev/null",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "NumberOfPasswordPrompts=1",
            "-o",
            "ConnectTimeout=5",
            "-P",
            str(port),
            "buildbot@127.0.0.1",
        ),
        environment=_ssh_environment(password, tmp_path),
        stdin=commands.encode("utf-8"),
    )
    assert project_readme.exists(), stdout + stderr
    assert download.exists(), stdout + stderr
    assert "FieldKit" in project_readme.read_text(encoding="utf-8")
    assert download.read_text(encoding="utf-8") == upload.read_text(encoding="utf-8")


def _smb_round_trip(port: int, password: str) -> None:
    server = "127.0.0.1"
    share = rf"\\{server}\Engineering"
    remote_write = share + r"\fieldkit-ios\squirrelops-acceptance.txt"
    try:
        smbclient.register_session(
            server,
            username="buildbot",
            password=password,
            port=port,
            auth_protocol="ntlm",
        )
        assert "fieldkit-ios" in smbclient.listdir(share, port=port)
        with smbclient.open_file(
            share + r"\fieldkit-ios\README.md",
            mode="rb",
            port=port,
        ) as remote_readme:
            assert b"FieldKit" in remote_readme.read()
        with smbclient.open_file(remote_write, mode="wb", port=port) as remote_file:
            remote_file.write(b"SquirrelOps live SMB acceptance\n")
        with smbclient.open_file(remote_write, mode="rb", port=port) as remote_file:
            assert remote_file.read() == b"SquirrelOps live SMB acceptance\n"
        smbclient.remove(remote_write, port=port)
    finally:
        smbclient.delete_session(server, port=port)


async def _smb2_negotiate(port: int, *, half_close: bool = False) -> bytes:
    header = bytes.fromhex(
        "fe534d4240000000000000000000010000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
    )
    request = bytes.fromhex(
        "24000100010000000000000000112233445566778899aabbccddeeff"
        "00000000000000000202"
    )
    packet = header + request
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(len(packet).to_bytes(4, "big") + packet)
        await writer.drain()
        if half_close:
            writer.write_eof()
        response_length = int.from_bytes(
            await asyncio.wait_for(reader.readexactly(4), timeout=5), "big"
        )
        assert response_length <= 64 * 1024
        return await asyncio.wait_for(reader.readexactly(response_length), timeout=5)
    finally:
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_live_guest_serves_file_operations_and_isolates_host(
    tmp_path: Path,
) -> None:
    runtime = _required_path("SQUIRRELOPS_DECEPTION_RUNTIME")
    guest_bundle = _required_path("SQUIRRELOPS_GUEST_BUNDLE")
    persona = build_studio_mini_persona(
        b"live-guest-acceptance-secret!!".ljust(32, b"!"),
        datetime(2026, 8, 31, 16, 30, tzinfo=UTC),
    )
    telemetry: list[GuestConnectionTelemetry] = []
    controller = GuestRuntimeController(
        executable=runtime,
        bundle_root=guest_bundle,
        state_dir=tmp_path / "runtime-state",
        bind_address="127.0.0.1",
        persona=persona,
        # Permit either reviewed source-build inputs or immutable installed
        # inputs. The release runtime independently requires root-owned guest bytes.
        trusted_uids={0, os.getuid()},
        on_connection=telemetry.append,
    )

    ports = await controller.start()
    try:
        try:
            ssh_output = await _ssh_command(
                ports[22], persona.login_password, tmp_path, "sw_vers"
            )
            host_canary = tmp_path / "host-only-canary"
            host_canary.write_text("must not enter guest\n", encoding="utf-8")
            containment_output = await _ssh_command(
                ports[22],
                persona.login_password,
                tmp_path,
                "test ! -e "
                f"{shlex.quote(str(host_canary))} "
                "&& test \"$(ls -1 /sys/class/net)\" = lo "
                "&& printf 'isolated\\n'",
            )
            guest_layout = await _ssh_command(
                ports[22],
                persona.login_password,
                tmp_path,
                "id; "
                "stat -c '%U %G %a %n' /Users/buildbot "
                "/Users/buildbot/Projects /Users/buildbot/Builds; "
                "find /Users/buildbot -maxdepth 5 -type f -print | sort",
            )
            assert "/Users/buildbot/Projects/fieldkit-ios/README.md" in guest_layout
            await _sftp_round_trip(ports[22], persona.login_password, tmp_path)
            smb_response = await _smb2_negotiate(ports[445])
            await asyncio.to_thread(
                _smb_round_trip,
                ports[445],
                persona.login_password,
            )
            # More than the 16-slot admission pool, sequentially: both normal
            # closes and write-side EOF must release their relay ownership.
            for attempt in range(20):
                response = await _smb2_negotiate(ports[445], half_close=attempt % 2 == 0)
                assert response.startswith(b"\xfeSMB")
                # Authenticate rather than deliberately triggering OpenSSH's
                # existing penalty for repeated pre-auth disconnects.
                assert await _ssh_command(
                    ports[22], persona.login_password, tmp_path, "printf 'reconnected\\n'"
                ) == "reconnected\n"
                await asyncio.sleep(0.02)

            # Stop this disposable VM with both protocol relays still open.
            peers = [await asyncio.open_connection("127.0.0.1", ports[p]) for p in (22, 445)]
            process = controller._process
            try:
                await controller.stop()
                assert process is not None and process.returncode == 0
                for reader, _ in peers:
                    await asyncio.wait_for(reader.read(), timeout=5)
            finally:
                for _, writer in peers:
                    writer.close()
                    await writer.wait_closed()
        except BaseException as exc:
            pytest.fail(f"{exc}\nGuest diagnostics:\n{controller.diagnostic_tail}")
    finally:
        await controller.stop()

    assert "ProductName:\t\tmacOS" in ssh_output
    assert "ProductVersion:\t\t15.7.9" in ssh_output
    assert containment_output == "isolated\n"
    assert smb_response.startswith(b"\xfeSMB")
    assert int.from_bytes(smb_response[12:14], "little") == 0
    assert {event.dest_port for event in telemetry} == {22, 445}
