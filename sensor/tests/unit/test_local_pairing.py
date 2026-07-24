"""Tests for fail-closed local-pairing peer authorization."""

from __future__ import annotations

import stat
import tempfile
from pathlib import Path

import pytest

from squirrelops_home_sensor.api.local_pairing import (
    LocalPairingServer,
    authorize_peer,
    verify_peer_application,
)

_REQUIREMENT = 'identifier "com.squirrelops.home" and anchor apple generic'
_ALLOW_APP = lambda pid, path, requirement: True  # noqa: E731
_DENY_APP = lambda pid, path, requirement: False  # noqa: E731


class TestAuthorizePeer:
    def test_root_is_allowed(self):
        assert authorize_peer(
            0,
            123,
            console_uid=501,
            allow_unsigned_local=False,
            allowed_app_path="/Applications/SquirrelOps Home.app/Contents/MacOS/SquirrelOpsHome",
            allowed_app_requirement=_REQUIREMENT,
            verify_application=_DENY_APP,
        )

    def test_console_user_requires_verified_installed_app(self):
        assert authorize_peer(
            501,
            123,
            console_uid=501,
            allow_unsigned_local=False,
            allowed_app_path="/Applications/SquirrelOps Home.app/Contents/MacOS/SquirrelOpsHome",
            allowed_app_requirement=_REQUIREMENT,
            verify_application=_ALLOW_APP,
        )
        assert not authorize_peer(
            501,
            123,
            console_uid=501,
            allow_unsigned_local=False,
            allowed_app_path="/Applications/SquirrelOps Home.app/Contents/MacOS/SquirrelOpsHome",
            allowed_app_requirement=_REQUIREMENT,
            verify_application=_DENY_APP,
        )

    def test_same_uid_process_is_rejected_without_app_identity(self):
        assert not authorize_peer(
            501,
            123,
            console_uid=501,
            allow_unsigned_local=False,
            allowed_app_path=None,
            allowed_app_requirement=_REQUIREMENT,
            verify_application=_ALLOW_APP,
        )

    def test_other_and_missing_uids_are_rejected(self):
        for uid in (None, 502):
            assert not authorize_peer(
                uid,
                123,
                console_uid=501,
                allow_unsigned_local=False,
                allowed_app_path="/app",
                allowed_app_requirement=_REQUIREMENT,
                verify_application=_ALLOW_APP,
            )

    def test_unsigned_console_mode_must_be_explicit(self):
        assert authorize_peer(
            501,
            123,
            console_uid=501,
            allow_unsigned_local=True,
            allowed_app_path=None,
            allowed_app_requirement=None,
            verify_application=_DENY_APP,
        )

    def test_signature_requirement_is_mandatory(self):
        assert not authorize_peer(
            501,
            123,
            console_uid=501,
            allow_unsigned_local=False,
            allowed_app_path="/app",
            allowed_app_requirement=None,
            verify_application=_ALLOW_APP,
        )


def test_verify_application_enforces_designated_requirement(monkeypatch, tmp_path):
    import squirrelops_home_sensor.api.local_pairing as local_pairing

    executable = tmp_path / "SquirrelOpsHome"
    executable.write_bytes(b"binary")
    captured: list[str] = []

    class _Result:
        returncode = 0

    monkeypatch.setattr(local_pairing, "_exe_path_for_pid", lambda pid: str(executable))

    def fake_run(args, **kwargs):
        del kwargs
        captured.extend(args)
        return _Result()

    monkeypatch.setattr(local_pairing.subprocess, "run", fake_run)
    assert verify_peer_application(123, str(executable), _REQUIREMENT)
    assert f"-R={_REQUIREMENT}" in captured
    assert "-R" not in captured


class _FakeSock:
    def __init__(self, uid, pid):
        self.uid = uid
        self.pid = pid


def test_server_uses_peer_credentials(monkeypatch, tmp_path):
    import squirrelops_home_sensor.api.local_pairing as local_pairing

    monkeypatch.setattr(local_pairing, "get_peer_uid", lambda sock: sock.uid)
    monkeypatch.setattr(local_pairing, "get_peer_pid", lambda sock: sock.pid)
    server = LocalPairingServer(
        str(tmp_path / "pairing.sock"),
        lambda: "ABCD-EFGH-JKMP-QRST-VWXY",
        allowed_app_path="/Applications/SquirrelOps Home.app/Contents/MacOS/SquirrelOpsHome",
        allowed_app_requirement=_REQUIREMENT,
        console_uid_provider=lambda: 501,
        verify_application=_ALLOW_APP,
    )
    assert server.is_authorized(_FakeSock(501, 999))
    assert not server.is_authorized(_FakeSock(777, 999))


@pytest.mark.asyncio
async def test_server_refuses_to_replace_non_socket(tmp_path):
    socket_path = tmp_path / "run" / "pairing.sock"
    socket_path.parent.mkdir()
    socket_path.write_text("do not replace")
    server = LocalPairingServer(
        str(socket_path),
        lambda: "ABCD-EFGH-JKMP-QRST-VWXY",
        allowed_app_path="/app",
        allowed_app_requirement=_REQUIREMENT,
    )
    with pytest.raises(RuntimeError, match="non-socket"):
        await server.start()
    assert socket_path.read_text() == "do not replace"


@pytest.mark.asyncio
async def test_server_creates_expected_filesystem_modes():
    with tempfile.TemporaryDirectory(prefix="sqop-", dir="/tmp") as directory:
        socket_path = Path(directory) / "run" / "pairing.sock"
        server = LocalPairingServer(
            str(socket_path),
            lambda: "ABCD-EFGH-JKMP-QRST-VWXY",
            allowed_app_path="/app",
            allowed_app_requirement=_REQUIREMENT,
        )
        await server.start()
        try:
            assert stat.S_IMODE(socket_path.parent.stat().st_mode) == 0o755
            assert stat.S_IMODE(socket_path.stat().st_mode) == 0o666
        finally:
            await server.stop()
