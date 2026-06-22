"""Local pairing over a peer-credential-verified Unix domain socket.

The previous ``GET /pairing/local/code`` loopback-TCP endpoint disclosed the
pairing code to *any* local process, which could then self-pair and obtain a
CA-signed client certificate. This module replaces it with a Unix-domain socket
on which the sensor inspects the connecting peer before disclosing the code:

1. The peer UID must be root or the current console (logged-in) user. Loopback
   TCP cannot carry peer credentials; a Unix socket can (``getpeereid``).
2. If a code-signature requirement is configured (production, where the app is
   signed/notarized), the peer's executable must satisfy it (``codesign -R``).
   When unset (e.g. a dev build that is only ad-hoc signed) the UID check still
   applies, which is already stricter than the old "any local process" trust.

The authorization decision (:func:`authorize_peer`) is a pure function so it can
be unit-tested without a real signed peer; the OS-specific credential lookups
are thin wrappers around libc / libproc / codesign.
"""

from __future__ import annotations

import asyncio
import ctypes
import ctypes.util
import json
import logging
import os
import struct
import subprocess
from collections.abc import Callable

logger = logging.getLogger(__name__)

# macOS getsockopt level/option for the peer PID of a Unix socket.
_SOL_LOCAL = 0
_LOCAL_PEERPID = 0x002
_PROC_PIDPATHINFO_MAXSIZE = 4096


def authorize_peer(
    uid: int | None,
    pid: int | None,
    *,
    allowed_uids: set[int],
    code_requirement: str | None,
    verify_signature: Callable[[int, str], bool],
) -> bool:
    """Decide whether a connecting peer may receive the pairing code.

    The peer's UID must be in ``allowed_uids``. If ``code_requirement`` is set,
    the peer's process must also satisfy it via ``verify_signature``.
    """
    if uid is None or uid not in allowed_uids:
        return False
    if code_requirement:
        if pid is None or not verify_signature(pid, code_requirement):
            return False
    return True


def console_user_uid() -> int | None:
    """UID of the current console (logged-in) user, via the owner of /dev/console."""
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
    except (OSError, AttributeError):
        return None


def get_peer_pid(sock) -> int | None:
    """Peer PID of a connected Unix socket (macOS LOCAL_PEERPID)."""
    try:
        raw = sock.getsockopt(_SOL_LOCAL, _LOCAL_PEERPID, 4)
        return struct.unpack("i", raw)[0]
    except OSError:
        return None


def _exe_path_for_pid(pid: int) -> str | None:
    try:
        libproc = ctypes.CDLL(ctypes.util.find_library("proc"), use_errno=True)
        buf = ctypes.create_string_buffer(_PROC_PIDPATHINFO_MAXSIZE)
        n = libproc.proc_pidpath(pid, buf, _PROC_PIDPATHINFO_MAXSIZE)
        if n <= 0:
            return None
        return buf.value.decode()
    except (OSError, AttributeError):
        return None


def verify_peer_code_signature(pid: int, requirement: str) -> bool:
    """Return True if the process ``pid`` satisfies the codesign ``requirement``."""
    path = _exe_path_for_pid(pid)
    if not path:
        return False
    try:
        result = subprocess.run(
            ["/usr/bin/codesign", "--verify", "-R", requirement, "--", path],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, OSError):
        logger.debug("codesign verification failed for pid %s", pid, exc_info=True)
        return False


class LocalPairingServer:
    """Serves the current pairing code to verified local peers over a Unix socket.

    Parameters
    ----------
    socket_path:
        Filesystem path for the listening Unix socket.
    get_code:
        Callable returning the current pairing code (refreshing it as needed).
    code_requirement:
        Optional ``codesign`` requirement string the peer must satisfy.
    """

    def __init__(
        self,
        socket_path: str,
        get_code: Callable[[], str],
        *,
        code_requirement: str | None = None,
        console_uid_provider: Callable[[], int | None] = console_user_uid,
        verify_signature: Callable[[int, str], bool] = verify_peer_code_signature,
    ) -> None:
        self._socket_path = socket_path
        self._get_code = get_code
        self._code_requirement = code_requirement
        self._console_uid_provider = console_uid_provider
        self._verify_signature = verify_signature
        self._server: asyncio.AbstractServer | None = None

    def _allowed_uids(self) -> set[int]:
        allowed = {0}
        console = self._console_uid_provider()
        if console is not None:
            allowed.add(console)
        return allowed

    def is_authorized(self, sock) -> bool:
        uid = get_peer_uid(sock)
        pid = get_peer_pid(sock)
        ok = authorize_peer(
            uid,
            pid,
            allowed_uids=self._allowed_uids(),
            code_requirement=self._code_requirement,
            verify_signature=self._verify_signature,
        )
        if not ok:
            logger.warning("Local pairing: rejected peer uid=%s pid=%s", uid, pid)
        return ok

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            sock = writer.get_extra_info("socket")
            if sock is None or not self.is_authorized(sock):
                writer.write(b'{"error": "unauthorized"}\n')
                await writer.drain()
                return
            payload = json.dumps({"code": self._get_code()}) + "\n"
            writer.write(payload.encode())
            await writer.drain()
        except Exception:
            logger.exception("Local pairing handler error")
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def start(self) -> None:
        # Remove any stale socket, then listen. The socket is world-connectable
        # (0660 would block the console user if owned by root); authorization is
        # enforced per connection by is_authorized(), not the filesystem bits.
        try:
            os.unlink(self._socket_path)
        except FileNotFoundError:
            pass
        self._server = await asyncio.start_unix_server(self._handle, path=self._socket_path)
        os.chmod(self._socket_path, 0o666)
        logger.info("Local pairing socket listening at %s", self._socket_path)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        try:
            os.unlink(self._socket_path)
        except FileNotFoundError:
            pass
