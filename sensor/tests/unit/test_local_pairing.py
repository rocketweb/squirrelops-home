"""Tests for the local-pairing peer authorization logic (F10)."""

from __future__ import annotations

from squirrelops_home_sensor.api.local_pairing import (
    LocalPairingServer,
    authorize_peer,
)

_ALLOW_SIG = lambda pid, req: True  # noqa: E731
_DENY_SIG = lambda pid, req: False  # noqa: E731


class TestAuthorizePeer:
    def test_root_allowed_without_requirement(self):
        assert authorize_peer(0, 123, allowed_uids={0, 501},
                              code_requirement=None, verify_signature=_DENY_SIG) is True

    def test_console_user_allowed_without_requirement(self):
        assert authorize_peer(501, 123, allowed_uids={0, 501},
                              code_requirement=None, verify_signature=_DENY_SIG) is True

    def test_other_uid_rejected(self):
        assert authorize_peer(502, 123, allowed_uids={0, 501},
                              code_requirement=None, verify_signature=_ALLOW_SIG) is False

    def test_missing_uid_rejected(self):
        assert authorize_peer(None, 123, allowed_uids={0, 501},
                              code_requirement=None, verify_signature=_ALLOW_SIG) is False

    def test_requirement_enforced_when_set(self):
        # Allowed UID but failing signature -> rejected.
        assert authorize_peer(501, 123, allowed_uids={0, 501},
                              code_requirement="anchor apple", verify_signature=_DENY_SIG) is False
        # Allowed UID and passing signature -> allowed.
        assert authorize_peer(501, 123, allowed_uids={0, 501},
                              code_requirement="anchor apple", verify_signature=_ALLOW_SIG) is True

    def test_requirement_with_missing_pid_rejected(self):
        assert authorize_peer(501, None, allowed_uids={0, 501},
                              code_requirement="anchor apple", verify_signature=_ALLOW_SIG) is False


class _FakeSock:
    """A stand-in socket whose peer creds are supplied directly."""
    def __init__(self, uid, pid):
        self._uid = uid
        self._pid = pid


class TestServerAuthorization:
    def _server(self, *, console_uid, requirement=None, verify=_ALLOW_SIG):
        srv = LocalPairingServer(
            "/tmp/does-not-matter.sock",
            get_code=lambda: "123456",
            code_requirement=requirement,
            console_uid_provider=lambda: console_uid,
            verify_signature=verify,
        )
        return srv

    def test_is_authorized_accepts_console_user(self, monkeypatch):
        import squirrelops_home_sensor.api.local_pairing as lp
        monkeypatch.setattr(lp, "get_peer_uid", lambda s: s._uid)
        monkeypatch.setattr(lp, "get_peer_pid", lambda s: s._pid)
        srv = self._server(console_uid=501)
        assert srv.is_authorized(_FakeSock(uid=501, pid=999)) is True

    def test_is_authorized_rejects_other_user(self, monkeypatch):
        import squirrelops_home_sensor.api.local_pairing as lp
        monkeypatch.setattr(lp, "get_peer_uid", lambda s: s._uid)
        monkeypatch.setattr(lp, "get_peer_pid", lambda s: s._pid)
        srv = self._server(console_uid=501)
        assert srv.is_authorized(_FakeSock(uid=777, pid=999)) is False

    def test_is_authorized_enforces_signature_when_required(self, monkeypatch):
        import squirrelops_home_sensor.api.local_pairing as lp
        monkeypatch.setattr(lp, "get_peer_uid", lambda s: s._uid)
        monkeypatch.setattr(lp, "get_peer_pid", lambda s: s._pid)
        srv = self._server(console_uid=501, requirement="anchor apple generic", verify=_DENY_SIG)
        assert srv.is_authorized(_FakeSock(uid=501, pid=999)) is False
