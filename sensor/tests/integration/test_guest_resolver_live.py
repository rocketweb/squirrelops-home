"""Opt-in loopback-only timing/identity check of a fresh Samba process."""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from smbprotocol.connection import Connection
from smbprotocol.exceptions import MoreProcessingRequired
from smbprotocol.session import Session, SMB2SessionSetupResponse
from spnego._ntlm_raw.messages import AvId, Challenge

from squirrelops_home_sensor.decoys.deep.guest_runtime import GuestRuntimeController
from squirrelops_home_sensor.decoys.deep.persona import build_studio_mini_persona
from tests.integration.test_deep_deception_live_guest import (
    _required_path,
    _smb_round_trip,
    _ssh_command,
)


class IdentityConnection(Connection):
    """Record only synthetic server identity, never client tokens or passwords."""

    identity: dict[str, str]

    def receive(self, *args, **kwargs):
        try:
            return super().receive(*args, **kwargs)
        except MoreProcessingRequired as exc:
            response = SMB2SessionSetupResponse()
            response.unpack(exc.header["data"].get_value())
            token = response["buffer"].get_value()
            offset = token.find(b"NTLMSSP\0")
            assert offset >= 0
            challenge = Challenge.unpack(token[offset:])
            self.identity = {
                key.name: challenge.target_info.get(key, "") for key in (
                    AvId.nb_computer_name, AvId.nb_domain_name,
                    AvId.dns_computer_name, AvId.dns_domain_name,
                )
            }
            raise


def _handshake(port: int, password: str) -> dict:
    connection = IdentityConnection(uuid.uuid4(), "127.0.0.1", port, require_signing=False)
    start = time.monotonic()
    try:
        connection.connect(timeout=30)
        negotiated = time.monotonic()
        session = Session(connection, username="buildbot", password=password, auth_protocol="ntlm")
        session.connect()
        authenticated = time.monotonic()
        return {
            "negotiate_seconds": round(negotiated - start, 3),
            "authenticate_seconds": round(authenticated - negotiated, 3),
            "total_seconds": round(authenticated - start, 3),
            "dialect": connection.dialect,
            "identity": connection.identity,
        }
    finally:
        connection.disconnect(close=True)


@pytest.mark.asyncio
async def test_fresh_guest_smb_handshake_and_local_identity(tmp_path: Path) -> None:
    runtime = _required_path("SQUIRRELOPS_DECEPTION_RUNTIME")
    bundle = _required_path("SQUIRRELOPS_GUEST_BUNDLE")
    persona = build_studio_mini_persona(
        b"resolver-regression-synthetic-key".ljust(32, b"!"),
        datetime(2026, 10, 1, tzinfo=UTC),
    )
    controller = GuestRuntimeController(
        executable=runtime, bundle_root=bundle, state_dir=tmp_path / "state",
        bind_address="127.0.0.1", persona=persona, trusted_uids={0, os.getuid()},
    )
    ports = await controller.start()
    try:
        # Runtime readiness covers relay listeners, not completion of guest init.
        # Only observe an SSH banner before the first SMB connection, no login.
        for _ in range(50):
            reader, writer = await asyncio.open_connection("127.0.0.1", ports[22])
            try:
                banner = await asyncio.wait_for(reader.readline(), timeout=2)
            finally:
                writer.close()
                await writer.wait_closed()
            if banner.startswith(b"SSH-2.0-"):
                break
            await asyncio.sleep(0.2)
        else:
            pytest.fail("guest SSH readiness banner did not arrive")
        timing = await asyncio.to_thread(_handshake, ports[445], persona.login_password)
        print("SMB_FRESH_GUEST " + json.dumps(timing, sort_keys=True))
        assert timing["total_seconds"] < 5, timing
        assert timing["identity"] == {
            "nb_computer_name": "STUDIO-MINI", "nb_domain_name": "STUDIO-MINI",
            "dns_computer_name": "studio-mini.local", "dns_domain_name": "local",
        }
        identity = await _ssh_command(
            ports[22], persona.login_password, tmp_path,
            "hostname; cat /etc/hosts /etc/resolv.conf; "
            "getent hosts studio-mini; getent hosts studio-mini.local; "
            "ls -1 /sys/class/net",
        )
        assert "buildkitsandbox" not in identity
        assert "192.168.65.7" not in identity
        assert identity.startswith("studio-mini\n")
        assert "127.0.0.1 studio-mini.local studio-mini localhost" in identity
        assert identity.endswith("lo\n")
        await asyncio.to_thread(_smb_round_trip, ports[445], persona.login_password)
    finally:
        process = controller._process
        await controller.stop()
        assert process is not None and process.returncode == 0
