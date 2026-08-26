"""Tests for helper-mediated local certificate enrollment."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import aiosqlite
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.x509.oid import NameOID

from squirrelops_home_sensor.api.local_enrollment import (
    MAX_PENDING_ENROLLMENTS,
    LocalEnrollmentAuthority,
    LocalEnrollmentError,
    authorize_enrollment_peer,
)
from squirrelops_home_sensor.api.routes_pairing import _generate_ca
from squirrelops_home_sensor.db.schema import create_all_tables


def _csr(common_name: str = "Matt's Mac") -> tuple[object, str]:
    private_key = generate_private_key(SECP256R1())
    request = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(private_key, hashes.SHA256())
    )
    return private_key, request.public_bytes(serialization.Encoding.PEM).decode()


@pytest.mark.asyncio
async def test_enrollment_is_pending_until_mtls_key_possession_is_proven() -> None:
    db = await aiosqlite.connect(":memory:")
    db.row_factory = aiosqlite.Row
    await create_all_tables(db)
    ca_key, ca_cert = _generate_ca("Local Sensor")
    client_key, csr_pem = _csr()
    authority = LocalEnrollmentAuthority(
        db=db,
        ca_key=ca_key,
        ca_cert=ca_cert,
        sensor_id="sensor-local",
        sensor_name="Local Sensor",
    )

    response = await authority.enroll(
        request_id="8e6b6d86-72bb-4e65-99c3-f155f10fdf4f",
        client_name="Matt's Mac",
        csr_pem=csr_pem,
    )

    client_cert = x509.load_pem_x509_certificate(response.client_cert_pem.encode())
    assert client_cert.public_key().public_numbers() == client_key.public_key().public_numbers()
    row = await (
        await db.execute("SELECT * FROM pairing WHERE id = ?", (response.pairing_id,))
    ).fetchone()
    assert row["status"] == "pending"
    assert row["is_local"] == 1

    assert not await authority.confirm(
        request_id=response.request_id,
        cert_fingerprint="sha256:wrong",
    )
    assert await authority.confirm(
        request_id=response.request_id,
        cert_fingerprint=response.cert_fingerprint,
    ) == response.pairing_id
    row = await (
        await db.execute("SELECT * FROM pairing WHERE id = ?", (response.pairing_id,))
    ).fetchone()
    assert row["status"] == "active"
    assert row["enrollment_client_cert_pem"] is None
    assert await authority.confirm(
        request_id=response.request_id,
        cert_fingerprint=response.cert_fingerprint,
    ) == response.pairing_id
    await db.close()


@pytest.mark.asyncio
async def test_expired_pending_enrollment_cannot_be_confirmed() -> None:
    db = await aiosqlite.connect(":memory:")
    db.row_factory = aiosqlite.Row
    await create_all_tables(db)
    ca_key, ca_cert = _generate_ca("Local Sensor")
    _, csr_pem = _csr()
    clock = [datetime(2026, 8, 22, tzinfo=UTC)]
    authority = LocalEnrollmentAuthority(
        db=db,
        ca_key=ca_key,
        ca_cert=ca_cert,
        sensor_id="sensor-local",
        sensor_name="Local Sensor",
        now=lambda: clock[0],
    )
    response = await authority.enroll(
        request_id="8e6b6d86-72bb-4e65-99c3-f155f10fdf4f",
        client_name="Matt's Mac",
        csr_pem=csr_pem,
    )

    clock[0] += timedelta(seconds=301)

    assert await authority.confirm(
        request_id=response.request_id,
        cert_fingerprint=response.cert_fingerprint,
    ) is None
    row = await (
        await db.execute("SELECT status FROM pairing WHERE id = ?", (response.pairing_id,))
    ).fetchone()
    assert row["status"] == "pending"
    await db.close()


@pytest.mark.asyncio
async def test_retry_returns_the_same_pending_certificate() -> None:
    db = await aiosqlite.connect(":memory:")
    db.row_factory = aiosqlite.Row
    await create_all_tables(db)
    ca_key, ca_cert = _generate_ca("Local Sensor")
    _, csr_pem = _csr()
    authority = LocalEnrollmentAuthority(
        db=db,
        ca_key=ca_key,
        ca_cert=ca_cert,
        sensor_id="sensor-local",
        sensor_name="Local Sensor",
    )
    request = {
        "request_id": "fa30c034-e031-4b12-947a-01489b5d5e66",
        "client_name": "Matt's Mac",
        "csr_pem": csr_pem,
    }

    first = await authority.enroll(**request)
    second = await authority.enroll(**request)

    assert second == first
    count = await (await db.execute("SELECT COUNT(*) FROM pairing")).fetchone()
    assert count[0] == 1
    await db.close()


@pytest.mark.asyncio
async def test_replayed_request_id_cannot_change_the_key() -> None:
    db = await aiosqlite.connect(":memory:")
    db.row_factory = aiosqlite.Row
    await create_all_tables(db)
    ca_key, ca_cert = _generate_ca("Local Sensor")
    _, first_csr = _csr()
    _, second_csr = _csr()
    authority = LocalEnrollmentAuthority(
        db=db,
        ca_key=ca_key,
        ca_cert=ca_cert,
        sensor_id="sensor-local",
        sensor_name="Local Sensor",
        now=lambda: datetime(2026, 8, 22, tzinfo=UTC),
    )
    request_id = "c4595a69-e69a-40fd-af37-00620112bd6f"
    await authority.enroll(
        request_id=request_id,
        client_name="Matt's Mac",
        csr_pem=first_csr,
    )

    with pytest.raises(LocalEnrollmentError, match="request identifier"):
        await authority.enroll(
            request_id=request_id,
            client_name="Matt's Mac",
            csr_pem=second_csr,
        )
    await db.close()


@pytest.mark.asyncio
async def test_capacity_error_rolls_back_expired_enrollment_cleanup() -> None:
    db = await aiosqlite.connect(":memory:")
    db.row_factory = aiosqlite.Row
    await create_all_tables(db)
    now = datetime(2026, 8, 22, tzinfo=UTC)
    await db.execute(
        """INSERT INTO pairing
           (client_name, client_cert_fingerprint, is_local, paired_at,
            status, enrollment_expires_at)
           VALUES ('expired', 'sha256:expired', 1, ?, 'pending', ?)""",
        (now.isoformat(), (now - timedelta(seconds=1)).isoformat()),
    )
    await db.executemany(
        """INSERT INTO pairing
           (client_name, client_cert_fingerprint, is_local, paired_at,
            status, enrollment_expires_at)
           VALUES (?, ?, 1, ?, 'pending', ?)""",
        [
            (
                f"pending-{index}",
                f"sha256:pending-{index}",
                now.isoformat(),
                (now + timedelta(seconds=300)).isoformat(),
            )
            for index in range(MAX_PENDING_ENROLLMENTS)
        ],
    )
    await db.commit()
    ca_key, ca_cert = _generate_ca("Local Sensor")
    _, csr_pem = _csr()
    authority = LocalEnrollmentAuthority(
        db=db,
        ca_key=ca_key,
        ca_cert=ca_cert,
        sensor_id="sensor-local",
        sensor_name="Local Sensor",
        now=lambda: now,
    )

    with pytest.raises(LocalEnrollmentError, match="Too many pending"):
        await authority.enroll(
            request_id="3387d6a2-ea0e-4b23-a61a-7f81ef20ee44",
            client_name="Matt's Mac",
            csr_pem=csr_pem,
        )

    assert not db.in_transaction
    expired = await (
        await db.execute(
            "SELECT COUNT(*) FROM pairing WHERE client_name = 'expired'"
        )
    ).fetchone()
    assert expired[0] == 1
    await db.close()


def test_only_root_may_use_sensor_enrollment_socket() -> None:
    assert authorize_enrollment_peer(0)
    assert not authorize_enrollment_peer(501)
    assert not authorize_enrollment_peer(None)
