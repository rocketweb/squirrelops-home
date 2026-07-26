"""Local pairing over an authenticated Unix domain socket.

The setup key is never exposed through loopback HTTP or a shared temporary
file. Production accepts root or a running SquirrelOps app whose immutable
socket audit token satisfies the pinned dynamic code requirement. Source
builds can explicitly opt into console-UID authorization for development.
"""

from __future__ import annotations

import asyncio
import ctypes
import ctypes.util
import json
import logging
import os
import stat
import sys
from collections.abc import Callable
from pathlib import Path

logger = logging.getLogger(__name__)

# macOS getsockopt level/option for the audit token captured when the Unix
# socket connection is established.
_SOL_LOCAL = 0
_LOCAL_PEERTOKEN = 0x006
_AUDIT_TOKEN_SIZE = 32
_CF_STRING_ENCODING_UTF8 = 0x08000100


def authorize_peer(
    uid: int | None,
    audit_token: bytes | None,
    *,
    console_uid: int | None,
    allow_unsigned_local: bool,
    allowed_app_requirement: str | None,
    verify_application: Callable[[bytes, str], bool],
) -> bool:
    """Return whether a peer may receive the one-time setup key."""
    if uid is None:
        return False
    if uid == 0:
        return True
    if console_uid is None or uid != console_uid or audit_token is None:
        return False
    if allow_unsigned_local:
        return True
    if not allowed_app_requirement:
        return False
    return verify_application(audit_token, allowed_app_requirement)


def console_user_uid() -> int | None:
    """UID of the current console (logged-in) user."""
    try:
        return os.stat("/dev/console").st_uid
    except OSError:
        return None


def get_peer_uid(sock) -> int | None:
    """Peer UID of a connected Unix socket (macOS/BSD getpeereid)."""
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        uid = ctypes.c_uint32()
        gid = ctypes.c_uint32()
        if libc.getpeereid(sock.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
            return None
        return int(uid.value)
    except (OSError, AttributeError, TypeError):
        return None


def get_peer_audit_token(sock) -> bytes | None:
    """Immutable audit token captured for the connected Unix-socket peer."""
    try:
        token = sock.getsockopt(_SOL_LOCAL, _LOCAL_PEERTOKEN, _AUDIT_TOKEN_SIZE)
    except OSError:
        return None
    if len(token) != _AUDIT_TOKEN_SIZE:
        return None
    return token


def verify_peer_application(
    audit_token: bytes,
    allowed_app_requirement: str,
) -> bool:
    """Validate the connected process against a dynamic code requirement.

    ``LOCAL_PEERTOKEN`` binds the lookup to the socket peer captured at
    connection time, including its process generation. Resolving a PID to a
    filesystem path later would allow a connect-then-exec identity swap.
    """
    if sys.platform != "darwin" or len(audit_token) != _AUDIT_TOKEN_SIZE:
        return False

    security_path = ctypes.util.find_library("Security")
    core_foundation_path = ctypes.util.find_library("CoreFoundation")
    if not security_path or not core_foundation_path:
        return False

    core_foundation: ctypes.CDLL | None = None
    retained: list[int] = []
    try:
        security = ctypes.CDLL(security_path)
        core_foundation = ctypes.CDLL(core_foundation_path)

        core_foundation.CFDataCreate.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_long,
        ]
        core_foundation.CFDataCreate.restype = ctypes.c_void_p
        core_foundation.CFDictionaryCreate.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_long,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        core_foundation.CFDictionaryCreate.restype = ctypes.c_void_p
        core_foundation.CFStringCreateWithCString.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_uint32,
        ]
        core_foundation.CFStringCreateWithCString.restype = ctypes.c_void_p
        core_foundation.CFRelease.argtypes = [ctypes.c_void_p]
        core_foundation.CFRelease.restype = None

        security.SecCodeCopyGuestWithAttributes.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        security.SecCodeCopyGuestWithAttributes.restype = ctypes.c_int32
        security.SecRequirementCreateWithString.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        security.SecRequirementCreateWithString.restype = ctypes.c_int32
        security.SecCodeCheckValidity.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        security.SecCodeCheckValidity.restype = ctypes.c_int32

        token_buffer = (ctypes.c_ubyte * _AUDIT_TOKEN_SIZE).from_buffer_copy(
            audit_token
        )
        token_data = core_foundation.CFDataCreate(
            None,
            token_buffer,
            _AUDIT_TOKEN_SIZE,
        )
        if not token_data:
            return False
        retained.append(int(token_data))

        audit_key = ctypes.c_void_p.in_dll(
            security,
            "kSecGuestAttributeAudit",
        ).value
        if not audit_key:
            return False
        keys = (ctypes.c_void_p * 1)(audit_key)
        values = (ctypes.c_void_p * 1)(token_data)
        attributes = core_foundation.CFDictionaryCreate(
            None,
            keys,
            values,
            1,
            None,
            None,
        )
        if not attributes:
            return False
        retained.append(int(attributes))

        requirement_text = core_foundation.CFStringCreateWithCString(
            None,
            allowed_app_requirement.encode("utf-8"),
            _CF_STRING_ENCODING_UTF8,
        )
        if not requirement_text:
            return False
        retained.append(int(requirement_text))

        requirement = ctypes.c_void_p()
        if (
            security.SecRequirementCreateWithString(
                requirement_text,
                0,
                ctypes.byref(requirement),
            )
            != 0
            or not requirement.value
        ):
            return False
        requirement_value = requirement.value
        if requirement_value is None:
            return False
        retained.append(requirement_value)

        guest = ctypes.c_void_p()
        if (
            security.SecCodeCopyGuestWithAttributes(
                None,
                attributes,
                0,
                ctypes.byref(guest),
            )
            != 0
            or not guest.value
        ):
            return False
        guest_value = guest.value
        if guest_value is None:
            return False
        retained.append(guest_value)
        return (
            security.SecCodeCheckValidity(
                guest,
                0,
                requirement,
            )
            == 0
        )
    except (OSError, AttributeError, TypeError, ValueError):
        logger.debug("App audit-token verification failed", exc_info=True)
        return False
    finally:
        if core_foundation is not None:
            for item in reversed(retained):
                core_foundation.CFRelease(ctypes.c_void_p(item))


class LocalPairingServer:
    """Serve the setup key to a verified local app over a Unix socket."""

    def __init__(
        self,
        socket_path: str,
        get_code: Callable[[], str],
        *,
        allowed_app_requirement: str | None,
        allow_unsigned_local: bool = False,
        console_uid_provider: Callable[[], int | None] = console_user_uid,
        verify_application: Callable[[bytes, str], bool] = verify_peer_application,
    ) -> None:
        self._socket_path = Path(socket_path)
        self._get_code = get_code
        self._allowed_app_requirement = allowed_app_requirement
        self._allow_unsigned_local = allow_unsigned_local
        self._console_uid_provider = console_uid_provider
        self._verify_application = verify_application
        self._server: asyncio.AbstractServer | None = None

    def is_authorized(self, sock) -> bool:
        uid = get_peer_uid(sock)
        audit_token = get_peer_audit_token(sock)
        authorized = authorize_peer(
            uid,
            audit_token,
            console_uid=self._console_uid_provider(),
            allow_unsigned_local=self._allow_unsigned_local,
            allowed_app_requirement=self._allowed_app_requirement,
            verify_application=self._verify_application,
        )
        if not authorized:
            logger.warning(
                "Local pairing rejected peer uid=%s audit_token=%s",
                uid,
                "present" if audit_token is not None else "missing",
            )
        return authorized

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        del reader
        try:
            sock = writer.get_extra_info("socket")
            if sock is None or not self.is_authorized(sock):
                writer.write(b'{"error": "unauthorized"}\n')
                await writer.drain()
                return
            writer.write((json.dumps({"code": self._get_code()}) + "\n").encode())
            await writer.drain()
        except Exception:
            logger.exception("Local pairing handler error")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    def _remove_stale_socket(self) -> None:
        try:
            existing = self._socket_path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(existing.st_mode):
            raise RuntimeError(
                f"Refusing to replace non-socket local pairing path: {self._socket_path}"
            )
        self._socket_path.unlink()

    async def start(self) -> None:
        # The run directory is traversable but not writable by the desktop user.
        # Peer credentials and app identity remain the authorization boundary.
        self._socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        os.chmod(self._socket_path.parent, 0o755)
        self._remove_stale_socket()
        self._server = await asyncio.start_unix_server(
            self._handle, path=str(self._socket_path)
        )
        # The signed desktop app runs as the console user while the sensor runs
        # as _squirrelops. Filesystem mode permits the connection; getpeereid,
        # the captured audit token, and dynamic code validation authorize it.
        os.chmod(self._socket_path, 0o666)  # nosec B103
        logger.info("Local pairing socket listening at %s", self._socket_path)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        try:
            if stat.S_ISSOCK(self._socket_path.lstat().st_mode):
                self._socket_path.unlink()
        except FileNotFoundError:
            pass
