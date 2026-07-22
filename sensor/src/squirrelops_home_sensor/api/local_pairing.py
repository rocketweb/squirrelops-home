"""Local pairing over an authenticated Unix domain socket.

The setup key is never exposed through loopback HTTP or a shared temporary
file. Production accepts root or the exact installed SquirrelOps app binary,
after checking its executable path, code-signature integrity, and designated
code requirement. Source builds can explicitly opt into console-UID
authorization for development.
"""

from __future__ import annotations

import asyncio
import ctypes
import ctypes.util
import json
import logging
import os
import stat
import struct
import subprocess
from collections.abc import Callable
from pathlib import Path

logger = logging.getLogger(__name__)

# macOS getsockopt level/option for the peer PID of a Unix socket.
_SOL_LOCAL = 0
_LOCAL_PEERPID = 0x002
_PROC_PIDPATHINFO_MAXSIZE = 4096


def authorize_peer(
    uid: int | None,
    pid: int | None,
    *,
    console_uid: int | None,
    allow_unsigned_local: bool,
    allowed_app_path: str | None,
    allowed_app_requirement: str | None,
    verify_application: Callable[[int, str, str], bool],
) -> bool:
    """Return whether a peer may receive the one-time setup key."""
    if uid is None:
        return False
    if uid == 0:
        return True
    if console_uid is None or uid != console_uid or pid is None:
        return False
    if allow_unsigned_local:
        return True
    if not allowed_app_path or not allowed_app_requirement:
        return False
    return verify_application(pid, allowed_app_path, allowed_app_requirement)


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


def get_peer_pid(sock) -> int | None:
    """Peer PID of a connected Unix socket (macOS LOCAL_PEERPID)."""
    try:
        raw = sock.getsockopt(_SOL_LOCAL, _LOCAL_PEERPID, 4)
        return struct.unpack("i", raw)[0]
    except (OSError, struct.error):
        return None


def _exe_path_for_pid(pid: int) -> str | None:
    try:
        libproc = ctypes.CDLL(ctypes.util.find_library("proc"), use_errno=True)
        buf = ctypes.create_string_buffer(_PROC_PIDPATHINFO_MAXSIZE)
        length = libproc.proc_pidpath(pid, buf, _PROC_PIDPATHINFO_MAXSIZE)
        if length <= 0:
            return None
        return buf.value.decode()
    except (OSError, AttributeError, UnicodeDecodeError, TypeError):
        return None


def verify_peer_application(
    pid: int,
    allowed_app_path: str,
    allowed_app_requirement: str,
) -> bool:
    """Verify the peer path, signature integrity, and designated requirement."""
    executable = _exe_path_for_pid(pid)
    if not executable:
        return False
    try:
        if Path(executable).resolve(strict=True) != Path(allowed_app_path).resolve(strict=True):
            return False
        result = subprocess.run(
            [
                "/usr/bin/codesign",
                "--verify",
                "--strict",
                "-R",
                allowed_app_requirement,
                "--",
                executable,
            ],
            capture_output=True,
            timeout=10,
            check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        logger.debug("App identity verification failed for pid %s", pid, exc_info=True)
        return False


class LocalPairingServer:
    """Serve the setup key to a verified local app over a Unix socket."""

    def __init__(
        self,
        socket_path: str,
        get_code: Callable[[], str],
        *,
        allowed_app_path: str | None,
        allowed_app_requirement: str | None,
        allow_unsigned_local: bool = False,
        console_uid_provider: Callable[[], int | None] = console_user_uid,
        verify_application: Callable[[int, str, str], bool] = verify_peer_application,
    ) -> None:
        self._socket_path = Path(socket_path)
        self._get_code = get_code
        self._allowed_app_path = allowed_app_path
        self._allowed_app_requirement = allowed_app_requirement
        self._allow_unsigned_local = allow_unsigned_local
        self._console_uid_provider = console_uid_provider
        self._verify_application = verify_application
        self._server: asyncio.AbstractServer | None = None

    def is_authorized(self, sock) -> bool:
        uid = get_peer_uid(sock)
        pid = get_peer_pid(sock)
        authorized = authorize_peer(
            uid,
            pid,
            console_uid=self._console_uid_provider(),
            allow_unsigned_local=self._allow_unsigned_local,
            allowed_app_path=self._allowed_app_path,
            allowed_app_requirement=self._allowed_app_requirement,
            verify_application=self._verify_application,
        )
        if not authorized:
            logger.warning("Local pairing rejected peer uid=%s pid=%s", uid, pid)
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
        # as _squirrelops. Filesystem mode permits the connection; SO_PEERCRED,
        # exact executable matching, and codesign verification authorize it.
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
