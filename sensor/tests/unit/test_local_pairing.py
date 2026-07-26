"""Tests for fail-closed local-pairing peer authorization."""

from __future__ import annotations

import socket
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from squirrelops_home_sensor.api.local_pairing import (
    LocalPairingServer,
    authorize_peer,
    get_peer_audit_token,
    verify_peer_application,
)
from squirrelops_home_sensor.config import PairingConfig

_REQUIREMENT = (
    'identifier "com.squirrelops.home" and anchor apple generic and '
    'certificate leaf[subject.OU] = "PSQ5HK5U65"'
)
_TOKEN = bytes(range(32))
_ALLOW_APP = lambda token, requirement: True  # noqa: E731
_DENY_APP = lambda token, requirement: False  # noqa: E731


def test_production_app_requirement_pins_rocket_web_team():
    requirement = PairingConfig().allowed_app_requirement
    assert 'identifier "com.squirrelops.home"' in requirement
    assert 'certificate leaf[subject.OU] = "PSQ5HK5U65"' in requirement


class TestAuthorizePeer:
    def test_console_user_authorizes_captured_audit_token(self):
        audit_token = bytes(range(32))
        captured: list[tuple[bytes, str]] = []

        def verify(token: bytes, requirement: str) -> bool:
            captured.append((token, requirement))
            return True

        assert authorize_peer(
            501,
            audit_token,
            console_uid=501,
            allow_unsigned_local=False,
            allowed_app_requirement=_REQUIREMENT,
            verify_application=verify,
        )
        assert captured == [(audit_token, _REQUIREMENT)]

    def test_root_is_allowed(self):
        assert authorize_peer(
            0,
            None,
            console_uid=501,
            allow_unsigned_local=False,
            allowed_app_requirement=_REQUIREMENT,
            verify_application=_DENY_APP,
        )

    def test_console_user_requires_verified_installed_app(self):
        assert authorize_peer(
            501,
            _TOKEN,
            console_uid=501,
            allow_unsigned_local=False,
            allowed_app_requirement=_REQUIREMENT,
            verify_application=_ALLOW_APP,
        )
        assert not authorize_peer(
            501,
            _TOKEN,
            console_uid=501,
            allow_unsigned_local=False,
            allowed_app_requirement=_REQUIREMENT,
            verify_application=_DENY_APP,
        )

    def test_same_uid_process_is_rejected_without_audit_token(self):
        assert not authorize_peer(
            501,
            None,
            console_uid=501,
            allow_unsigned_local=False,
            allowed_app_requirement=_REQUIREMENT,
            verify_application=_ALLOW_APP,
        )

    def test_other_and_missing_uids_are_rejected(self):
        for uid in (None, 502):
            assert not authorize_peer(
                uid,
                _TOKEN,
                console_uid=501,
                allow_unsigned_local=False,
                allowed_app_requirement=_REQUIREMENT,
                verify_application=_ALLOW_APP,
            )

    def test_unsigned_console_mode_must_be_explicit(self):
        assert authorize_peer(
            501,
            _TOKEN,
            console_uid=501,
            allow_unsigned_local=True,
            allowed_app_requirement=None,
            verify_application=_DENY_APP,
        )

    def test_signature_requirement_is_mandatory(self):
        assert not authorize_peer(
            501,
            _TOKEN,
            console_uid=501,
            allow_unsigned_local=False,
            allowed_app_requirement=None,
            verify_application=_ALLOW_APP,
        )


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS Security.framework required")
def test_verify_application_binds_requirement_to_socket_audit_token():
    local, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        audit_token = get_peer_audit_token(local)
        assert audit_token is not None

        requirement_result = subprocess.run(
            ["/usr/bin/codesign", "-d", "-r-", "--", sys.executable],
            capture_output=True,
            text=True,
            check=False,
        )
        assert requirement_result.returncode == 0
        marker = "designated => "
        requirement_output = (
            requirement_result.stdout + "\n" + requirement_result.stderr
        )
        requirement_line = next(
            line
            for line in requirement_output.splitlines()
            if marker in line
        )
        requirement = requirement_line.split(marker, 1)[1]

        assert verify_peer_application(audit_token, requirement)
        assert not verify_peer_application(
            audit_token,
            'identifier "invalid.squirrelops.test"',
        )
    finally:
        local.close()
        peer.close()


class _FakeSock:
    def __init__(self, uid, audit_token):
        self.uid = uid
        self.audit_token = audit_token


def test_server_uses_peer_credentials(monkeypatch, tmp_path):
    import squirrelops_home_sensor.api.local_pairing as local_pairing

    monkeypatch.setattr(local_pairing, "get_peer_uid", lambda sock: sock.uid)
    monkeypatch.setattr(
        local_pairing,
        "get_peer_audit_token",
        lambda sock: sock.audit_token,
        raising=False,
    )
    captured: list[tuple[bytes, str]] = []

    def verify(token: bytes, requirement: str) -> bool:
        captured.append((token, requirement))
        return True

    server = LocalPairingServer(
        str(tmp_path / "pairing.sock"),
        lambda: "ABCD-EFGH-JKMP-QRST-VWXY",
        allowed_app_requirement=_REQUIREMENT,
        console_uid_provider=lambda: 501,
        verify_application=verify,
    )
    token = bytes(range(32))
    assert server.is_authorized(_FakeSock(501, token))
    assert captured == [(token, _REQUIREMENT)]
    assert not server.is_authorized(_FakeSock(777, token))


@pytest.mark.asyncio
async def test_server_refuses_to_replace_non_socket(tmp_path):
    socket_path = tmp_path / "run" / "pairing.sock"
    socket_path.parent.mkdir()
    socket_path.write_text("do not replace")
    server = LocalPairingServer(
        str(socket_path),
        lambda: "ABCD-EFGH-JKMP-QRST-VWXY",
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
            allowed_app_requirement=_REQUIREMENT,
        )
        await server.start()
        try:
            assert stat.S_IMODE(socket_path.parent.stat().st_mode) == 0o755
            assert stat.S_IMODE(socket_path.stat().st_mode) == 0o666
        finally:
            await server.stop()
