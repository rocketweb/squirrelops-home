"""Launch and supervise the opaque, no-network macOS guest runtime."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from squirrelops_home_sensor.decoys.deep.guest_bundle import (
    GuestBundle,
    GuestBundleError,
    load_guest_bundle,
)
from squirrelops_home_sensor.decoys.deep.persona import StudioMiniPersona
from squirrelops_home_sensor.decoys.deep.persona_archive import build_persona_archive

# Persona transfer, SSH, and SMB each permit 240 x 250ms retry backoff in the
# Swift runtime. Include 30 seconds for VM start/scheduling, while retaining an
# outer deadline for stalled Virtualization callbacks or persona writes.
_READY_TIMEOUT_SECONDS = 210.0
_STOP_TIMEOUT_SECONDS = 8.0
_MAX_READY_LINE_BYTES = 16 * 1024
_MAX_EVENT_LINE_BYTES = 16 * 1024
_MAX_STDERR_TAIL_BYTES = 16 * 1024

logger = logging.getLogger(__name__)


class GuestRuntimeError(RuntimeError):
    """Raised when the guest runtime cannot establish its reviewed boundary."""


@dataclass(frozen=True)
class GuestConnectionTelemetry:
    """A bounded connection event emitted by the signed runtime."""

    source_ip: str
    source_port: int
    dest_port: int
    protocol: str
    interaction_type: str
    timestamp: datetime


def _trusted_executable(path: Path, trusted_uids: set[int]) -> None:
    try:
        result = path.lstat()
    except OSError as exc:
        raise GuestRuntimeError("Guest runtime executable is unavailable") from exc
    if not stat.S_ISREG(result.st_mode):
        raise GuestRuntimeError("Guest runtime executable must be a regular file")
    if result.st_uid not in trusted_uids:
        raise GuestRuntimeError("Guest runtime executable has an untrusted owner")
    if result.st_mode & 0o022:
        raise GuestRuntimeError(
            "Guest runtime executable is writable by an untrusted account"
        )
    if result.st_mode & 0o111 == 0:
        raise GuestRuntimeError("Guest runtime file is not executable")


def _prepare_state_dir(path: Path, trusted_uids: set[int]) -> None:
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.chmod(0o700)
        result = path.lstat()
    except OSError as exc:
        raise GuestRuntimeError("Guest runtime state directory is unavailable") from exc
    if not stat.S_ISDIR(result.st_mode) or path.is_symlink():
        raise GuestRuntimeError("Guest runtime state path must be a real directory")
    if result.st_uid not in trusted_uids:
        raise GuestRuntimeError("Guest runtime state directory has an untrusted owner")
    if result.st_mode & 0o077:
        raise GuestRuntimeError("Guest runtime state directory is accessible to other users")


class GuestRuntimeController:
    """Validate artifacts and supervise one exact runtime subprocess."""

    def __init__(
        self,
        *,
        executable: Path,
        bundle_root: Path,
        state_dir: Path,
        bind_address: str,
        persona: StudioMiniPersona,
        trusted_uids: set[int] | None = None,
        state_uids: set[int] | None = None,
        on_connection: Callable[[GuestConnectionTelemetry], None] | None = None,
        on_exit: Callable[[int], None] | None = None,
    ) -> None:
        self._executable = executable
        self._bundle_root = bundle_root
        self._state_dir = state_dir
        self._bind_address = bind_address
        self._trusted_uids = {0} if trusted_uids is None else set(trusted_uids)
        self._state_uids = {os.getuid()} if state_uids is None else set(state_uids)
        self._persona = persona
        self._on_connection = on_connection
        self._on_exit = on_exit
        self._process: asyncio.subprocess.Process | None = None
        self._bundle: GuestBundle | None = None
        self._backend_ports: dict[int, int] = {}
        self._output_task: asyncio.Task[None] | None = None
        self._stderr_task: asyncio.Task[None] | None = None
        self._watch_task: asyncio.Task[None] | None = None
        self._stopping = False
        self._stderr_tail = bytearray()

    @property
    def backend_ports(self) -> dict[int, int]:
        return dict(self._backend_ports)

    @property
    def is_running(self) -> bool:
        process = self._process
        return process is not None and process.returncode is None

    @property
    def diagnostic_tail(self) -> str:
        """Return bounded guest/runtime diagnostics for local acceptance."""
        return bytes(self._stderr_tail).decode("utf-8", errors="replace")

    @staticmethod
    def _parse_ready(line: bytes) -> dict[int, int]:
        if not line or len(line) > _MAX_READY_LINE_BYTES:
            raise GuestRuntimeError("Guest runtime did not provide a bounded ready record")
        try:
            payload = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GuestRuntimeError("Guest runtime ready record is invalid") from exc
        if not isinstance(payload, dict) or set(payload) != {
            "status",
            "persona_id",
            "services",
        }:
            raise GuestRuntimeError("Guest runtime ready record has an invalid shape")
        if payload.get("status") != "ready":
            raise GuestRuntimeError("Guest runtime did not become ready")
        if payload.get("persona_id") != "studio-mini-v1":
            raise GuestRuntimeError("Guest runtime persona does not match its bundle")
        services = payload.get("services")
        if not isinstance(services, dict) or set(services) != {"22", "445"}:
            raise GuestRuntimeError("Guest runtime service set is not reviewed")
        backend_ports: dict[int, int] = {}
        for advertised in (22, 445):
            backend = services.get(str(advertised))
            if (
                not isinstance(backend, int)
                or isinstance(backend, bool)
                or not 1024 <= backend <= 65535
                or backend in {22, 445}
            ):
                raise GuestRuntimeError("Guest runtime returned an invalid backend port")
            backend_ports[advertised] = backend
        if len(set(backend_ports.values())) != len(backend_ports):
            raise GuestRuntimeError("Guest runtime backend ports must be unique")
        return backend_ports

    async def _terminate_process(self) -> None:
        self._stopping = True
        process = self._process
        self._process = None
        self._backend_ports = {}
        output_task = self._output_task
        self._output_task = None
        stderr_task = self._stderr_task
        self._stderr_task = None
        watch_task = self._watch_task
        self._watch_task = None
        if process is not None and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=_STOP_TIMEOUT_SECONDS)
            except TimeoutError:
                process.kill()
                await process.wait()
        if output_task is not None:
            try:
                await asyncio.wait_for(output_task, timeout=1.0)
            except TimeoutError:
                output_task.cancel()
                await asyncio.gather(output_task, return_exceptions=True)
        if stderr_task is not None:
            try:
                await asyncio.wait_for(stderr_task, timeout=1.0)
            except TimeoutError:
                stderr_task.cancel()
                await asyncio.gather(stderr_task, return_exceptions=True)
        if watch_task is not None and watch_task is not asyncio.current_task():
            try:
                await asyncio.wait_for(watch_task, timeout=1.0)
            except TimeoutError:
                watch_task.cancel()
                await asyncio.gather(watch_task, return_exceptions=True)
        self._stopping = False

    async def _drain_stderr(self, stream: asyncio.StreamReader) -> None:
        while True:
            chunk = await stream.read(4096)
            if not chunk:
                return
            self._stderr_tail.extend(chunk)
            if len(self._stderr_tail) > _MAX_STDERR_TAIL_BYTES:
                del self._stderr_tail[:-_MAX_STDERR_TAIL_BYTES]

    @staticmethod
    def _parse_connection_event(line: bytes) -> GuestConnectionTelemetry:
        if not line or len(line) > _MAX_EVENT_LINE_BYTES:
            raise ValueError("runtime event line is outside the reviewed limit")
        try:
            payload = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("runtime event is not valid JSON") from exc
        expected = {
            "event",
            "source_ip",
            "source_port",
            "dest_port",
            "protocol",
            "interaction_type",
            "timestamp",
        }
        if not isinstance(payload, dict) or set(payload) != expected:
            raise ValueError("runtime event shape is not reviewed")
        if payload["event"] != "connection" or payload["protocol"] != "tcp":
            raise ValueError("runtime event kind is not reviewed")
        try:
            source_ip = str(ipaddress.IPv4Address(payload["source_ip"]))
        except (ValueError, TypeError) as exc:
            raise ValueError("runtime source address is invalid") from exc
        source_port = payload["source_port"]
        dest_port = payload["dest_port"]
        if (
            not isinstance(source_port, int)
            or isinstance(source_port, bool)
            or not 1 <= source_port <= 65535
            or dest_port not in {22, 445}
        ):
            raise ValueError("runtime event port is invalid")
        expected_interaction = {22: "ssh.connection", 445: "smb.connection"}
        interaction_type = payload["interaction_type"]
        if interaction_type != expected_interaction[dest_port]:
            raise ValueError("runtime interaction type does not match its service")
        timestamp_value = payload["timestamp"]
        if not isinstance(timestamp_value, str) or len(timestamp_value) > 64:
            raise ValueError("runtime event timestamp is invalid")
        try:
            timestamp = datetime.fromisoformat(timestamp_value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("runtime event timestamp is invalid") from exc
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("runtime event timestamp must include a timezone")
        return GuestConnectionTelemetry(
            source_ip=source_ip,
            source_port=source_port,
            dest_port=dest_port,
            protocol="tcp",
            interaction_type=interaction_type,
            timestamp=timestamp.astimezone(UTC),
        )

    async def _drain_output(self, stream: asyncio.StreamReader) -> None:
        while True:
            try:
                line = await stream.readline()
            except (ValueError, asyncio.LimitOverrunError):
                logger.warning("Deep-decoy runtime emitted an oversized telemetry record")
                return
            if not line:
                return
            try:
                event = self._parse_connection_event(line)
            except ValueError:
                logger.warning("Deep-decoy runtime emitted invalid telemetry")
                continue
            callback = self._on_connection
            if callback is not None:
                try:
                    callback(event)
                except Exception:
                    logger.exception("Deep-decoy runtime telemetry callback failed")

    async def _watch_process(self, process: asyncio.subprocess.Process) -> None:
        returncode = await process.wait()
        if process is not self._process:
            return
        self._backend_ports = {}
        if self._stopping:
            return
        callback = self._on_exit
        if callback is not None:
            try:
                callback(returncode)
            except Exception:
                logger.exception("Deep-decoy runtime exit callback failed")

    async def start(self) -> dict[int, int]:
        if self.is_running:
            raise GuestRuntimeError("Guest runtime is already running")
        if self._process is not None:
            await self._terminate_process()
        if not self._trusted_uids:
            raise GuestRuntimeError("Guest runtime requires a trusted owner")
        _trusted_executable(self._executable, self._trusted_uids)
        try:
            bundle = load_guest_bundle(
                self._bundle_root,
                trusted_uids=self._trusted_uids,
            )
        except GuestBundleError as exc:
            raise GuestRuntimeError(str(exc)) from exc
        if not self._state_uids:
            raise GuestRuntimeError("Guest runtime requires a trusted state owner")
        _prepare_state_dir(self._state_dir, self._state_uids)
        try:
            bind_address = ipaddress.IPv4Address(self._bind_address)
        except ValueError as exc:
            raise GuestRuntimeError("Guest runtime bind address is invalid") from exc
        if bind_address.is_unspecified or bind_address.is_multicast:
            raise GuestRuntimeError("Guest runtime bind address is unsafe")

        environment = {
            "PATH": "/usr/bin:/bin",
            "TMPDIR": str(self._state_dir),
        }
        try:
            process = await asyncio.create_subprocess_exec(
                str(self._executable),
                "--bundle",
                str(bundle.root),
                "--state-dir",
                str(self._state_dir),
                "--bind-address",
                str(bind_address),
                stdout=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=environment,
                close_fds=True,
                start_new_session=True,
                limit=_MAX_READY_LINE_BYTES,
            )
        except OSError as exc:
            raise GuestRuntimeError("Guest runtime could not be launched") from exc
        self._process = process
        self._bundle = bundle
        assert process.stdout is not None
        assert process.stdin is not None
        assert process.stderr is not None
        self._stderr_tail.clear()
        self._stderr_task = asyncio.create_task(
            self._drain_stderr(process.stderr),
            name="deep-decoy-runtime-stderr",
        )
        try:
            persona_archive = build_persona_archive(self._persona)
            process.stdin.write(len(persona_archive).to_bytes(4, "big") + persona_archive)
            await process.stdin.drain()
            process.stdin.close()
            line = await asyncio.wait_for(
                process.stdout.readline(),
                timeout=_READY_TIMEOUT_SECONDS,
            )
            ports = self._parse_ready(line)
            await asyncio.sleep(0)
            if process.returncode is not None:
                raise GuestRuntimeError("Guest runtime exited after its ready record")
        except BaseException as exc:
            await self._terminate_process()
            detail = bytes(self._stderr_tail).decode("utf-8", errors="replace").strip()
            if isinstance(exc, GuestRuntimeError) and detail:
                raise GuestRuntimeError(f"{exc}: {detail}") from exc
            if detail:
                raise GuestRuntimeError(f"Guest runtime startup failed: {detail}") from exc
            raise
        self._backend_ports = ports
        self._output_task = asyncio.create_task(
            self._drain_output(process.stdout),
            name="deep-decoy-runtime-output",
        )
        self._watch_task = asyncio.create_task(
            self._watch_process(process),
            name="deep-decoy-runtime-watch",
        )
        return dict(ports)

    async def stop(self) -> None:
        """Apply the local kill switch and wait for complete process exit."""
        await self._terminate_process()
        self._bundle = None
