"""Root-helper-mediated local app certificate enrollment.

The sensor socket accepts only the root helper. It issues a short-lived pending
certificate, and the app must prove possession of the corresponding Keychain
private key over mTLS before the pairing becomes active.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import socket
import stat
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import aiosqlite
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.x509.oid import NameOID

from squirrelops_home_sensor.api.local_pairing import get_peer_uid
from squirrelops_home_sensor.api.pairing_authority import (
    cert_fingerprint,
    sign_client_cert,
)

logger = logging.getLogger(__name__)

ENROLLMENT_EXPIRY_SECONDS = 300
MAX_PENDING_ENROLLMENTS = 8
MAX_REQUEST_BYTES = 16_384
MAX_CSR_BYTES = 8_192
MAX_CLIENT_NAME_LENGTH = 128


class LocalEnrollmentError(ValueError):
    """A bounded, operator-safe local enrollment failure."""


@dataclass(frozen=True)
class LocalEnrollmentResponse:
    request_id: str
    pairing_id: int
    sensor_id: str
    sensor_name: str
    ca_cert_pem: str
    client_cert_pem: str
    cert_fingerprint: str


def authorize_enrollment_peer(uid: int | None) -> bool:
    """Only the root helper may ask the sensor to issue a local certificate."""
    return uid == 0


def _validated_request_id(value: str) -> str:
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise LocalEnrollmentError("Invalid enrollment request identifier.") from exc
    if str(parsed) != value.lower():
        raise LocalEnrollmentError("Invalid enrollment request identifier.")
    return str(parsed)


def _validated_client_name(value: str) -> str:
    if not isinstance(value, str):
        raise LocalEnrollmentError("Invalid client name.")
    normalized = value.strip()
    if not normalized or len(normalized) > MAX_CLIENT_NAME_LENGTH:
        raise LocalEnrollmentError("Invalid client name.")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in normalized):
        raise LocalEnrollmentError("Invalid client name.")
    return normalized


def _validated_csr(csr_pem: str, client_name: str) -> x509.CertificateSigningRequest:
    if not isinstance(csr_pem, str) or not 0 < len(csr_pem.encode()) <= MAX_CSR_BYTES:
        raise LocalEnrollmentError("Invalid certificate request.")
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except Exception as exc:
        raise LocalEnrollmentError("Invalid certificate request.") from exc
    if not csr.is_signature_valid:
        raise LocalEnrollmentError("Invalid certificate request signature.")
    common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(common_names) != 1 or common_names[0].value != client_name:
        raise LocalEnrollmentError("Certificate request identity does not match client name.")
    return csr


class LocalEnrollmentAuthority:
    """Issue, retry, and activate short-lived local app pairings."""

    def __init__(
        self,
        *,
        db: aiosqlite.Connection,
        ca_key: EllipticCurvePrivateKey,
        ca_cert: x509.Certificate,
        sensor_id: str,
        sensor_name: str,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._db = db
        self._ca_key = ca_key
        self._ca_cert = ca_cert
        self._sensor_id = sensor_id
        self._sensor_name = sensor_name
        self._now = now
        self._lock = asyncio.Lock()

    def _response_from_row(self, row) -> LocalEnrollmentResponse:
        return LocalEnrollmentResponse(
            request_id=row["enrollment_request_id"],
            pairing_id=int(row["id"]),
            sensor_id=self._sensor_id,
            sensor_name=self._sensor_name,
            ca_cert_pem=self._ca_cert.public_bytes(serialization.Encoding.PEM).decode(),
            client_cert_pem=row["enrollment_client_cert_pem"],
            cert_fingerprint=row["client_cert_fingerprint"],
        )

    async def enroll(
        self,
        *,
        request_id: str,
        client_name: str,
        csr_pem: str,
    ) -> LocalEnrollmentResponse:
        request_id = _validated_request_id(request_id)
        client_name = _validated_client_name(client_name)
        csr = _validated_csr(csr_pem, client_name)
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        csr_fingerprint = hashlib.sha256(csr_der).hexdigest()

        async with self._lock:
            try:
                now = self._now().astimezone(UTC)
                await self._db.execute(
                    "DELETE FROM pairing WHERE status = 'pending' "
                    "AND enrollment_expires_at <= ?",
                    (now.isoformat(),),
                )
                cursor = await self._db.execute(
                    "SELECT * FROM pairing WHERE enrollment_request_id = ?",
                    (request_id,),
                )
                existing = await cursor.fetchone()
                if existing is not None:
                    if existing["status"] != "pending":
                        raise LocalEnrollmentError(
                            "Enrollment request identifier was already used."
                        )
                    if (
                        existing["client_name"] != client_name
                        or existing["enrollment_csr_fingerprint"] != csr_fingerprint
                    ):
                        raise LocalEnrollmentError(
                            "Enrollment request identifier does not match the original request."
                        )
                    await self._db.commit()
                    return self._response_from_row(existing)

                cursor = await self._db.execute(
                    "SELECT COUNT(*) FROM pairing WHERE status = 'pending'"
                )
                pending_row = await cursor.fetchone()
                if pending_row is None:
                    raise RuntimeError("Local enrollment pending count was unavailable.")
                pending_count = int(pending_row[0])
                if pending_count >= MAX_PENDING_ENROLLMENTS:
                    raise LocalEnrollmentError("Too many pending local enrollments.")

                client_cert = sign_client_cert(csr, self._ca_key, self._ca_cert)
                client_cert_pem = client_cert.public_bytes(
                    serialization.Encoding.PEM
                ).decode()
                fingerprint = cert_fingerprint(client_cert)
                expires_at = now + timedelta(seconds=ENROLLMENT_EXPIRY_SECONDS)
                cursor = await self._db.execute(
                    """INSERT INTO pairing
                       (client_name, client_cert_fingerprint, is_local, paired_at,
                        status, enrollment_request_id, enrollment_csr_fingerprint,
                        enrollment_client_cert_pem, enrollment_expires_at)
                       VALUES (?, ?, 1, ?, 'pending', ?, ?, ?, ?)""",
                    (
                        client_name,
                        fingerprint,
                        now.isoformat(),
                        request_id,
                        csr_fingerprint,
                        client_cert_pem,
                        expires_at.isoformat(),
                    ),
                )
                pairing_id = cursor.lastrowid
                if pairing_id is None:
                    raise RuntimeError("Local enrollment did not return a pairing ID.")
                await self._db.commit()
                return LocalEnrollmentResponse(
                    request_id=request_id,
                    pairing_id=int(pairing_id),
                    sensor_id=self._sensor_id,
                    sensor_name=self._sensor_name,
                    ca_cert_pem=self._ca_cert.public_bytes(
                        serialization.Encoding.PEM
                    ).decode(),
                    client_cert_pem=client_cert_pem,
                    cert_fingerprint=fingerprint,
                )
            except BaseException:
                await self._db.rollback()
                raise

    async def confirm(self, *, request_id: str, cert_fingerprint: str) -> int | None:
        request_id = _validated_request_id(request_id)
        async with self._lock:
            now = self._now().astimezone(UTC).isoformat()
            await self._db.execute(
                """UPDATE pairing
                   SET status = 'active',
                       enrollment_csr_fingerprint = NULL,
                       enrollment_client_cert_pem = NULL,
                       enrollment_expires_at = NULL
                   WHERE status = 'pending'
                     AND enrollment_request_id = ?
                     AND client_cert_fingerprint = ?
                     AND enrollment_expires_at > ?""",
                (request_id, cert_fingerprint, now),
            )
            await self._db.commit()
            # This active-only lookup serves two purposes: it confirms that an
            # unexpired pending row changed state, and keeps retries idempotent
            # after a previous confirmation already activated the same row.
            cursor = await self._db.execute(
                """SELECT id FROM pairing
                   WHERE enrollment_request_id = ?
                     AND client_cert_fingerprint = ?
                     AND status = 'active'""",
                (request_id, cert_fingerprint),
            )
            row = await cursor.fetchone()
            return int(row[0]) if row is not None else None


class LocalEnrollmentServer:
    """Expose LocalEnrollmentAuthority only to the root helper over a UDS."""

    def __init__(self, socket_path: str, authority: LocalEnrollmentAuthority) -> None:
        self._socket_path = Path(socket_path)
        self._authority = authority
        self._server: asyncio.AbstractServer | None = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            sock = writer.get_extra_info("socket")
            if sock is None or not authorize_enrollment_peer(get_peer_uid(sock)):
                writer.write(b'{"error":"unauthorized"}\n')
                await writer.drain()
                return
            line = await reader.readline()
            if not line or len(line) > MAX_REQUEST_BYTES or not line.endswith(b"\n"):
                raise LocalEnrollmentError("Invalid enrollment request.")
            body = json.loads(line)
            if not isinstance(body, dict) or body.get("action") != "enroll":
                raise LocalEnrollmentError("Invalid enrollment action.")
            request_id = body.get("request_id")
            client_name = body.get("client_name")
            csr_pem = body.get("csr_pem")
            if (
                not isinstance(request_id, str)
                or not isinstance(client_name, str)
                or not isinstance(csr_pem, str)
            ):
                raise LocalEnrollmentError("Invalid enrollment request fields.")
            response = await self._authority.enroll(
                request_id=request_id,
                client_name=client_name,
                csr_pem=csr_pem,
            )
            writer.write((json.dumps(asdict(response), separators=(",", ":")) + "\n").encode())
            await writer.drain()
        except (LocalEnrollmentError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            logger.warning("Rejected local enrollment request: %s", exc)
            writer.write(b'{"error":"invalid_request"}\n')
            await writer.drain()
        except Exception:
            logger.exception("Local enrollment socket handler failed")
            writer.write(b'{"error":"internal_error"}\n')
            await writer.drain()
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
        if stat.S_ISDIR(existing.st_mode):
            raise RuntimeError(
                f"Refusing to replace enrollment directory: {self._socket_path}"
            )
        # The run directory belongs to the sensor account. Unlink the exact
        # stale pathname without following symlinks so an interrupted launch
        # cannot permanently prevent enrollment from starting.
        self._socket_path.unlink()

    async def start(self) -> None:
        self._socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        self._remove_stale_socket()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self._socket_path))
            # Set the pathname private before asyncio begins listening and can
            # accept a peer. The peer-UID check remains the authorization gate.
            os.chmod(self._socket_path, 0o600)
            listener.setblocking(False)
            self._server = await asyncio.start_unix_server(
                self._handle,
                sock=listener,
                limit=MAX_REQUEST_BYTES,
            )
        except BaseException:
            listener.close()
            try:
                if stat.S_ISSOCK(self._socket_path.lstat().st_mode):
                    self._socket_path.unlink()
            except FileNotFoundError:
                pass
            raise
        logger.info("Root-only local enrollment socket listening at %s", self._socket_path)

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
