"""Pairing routes: challenge-response protocol, cert exchange, unpair."""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
import logging
import os
import secrets
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

import aiosqlite
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePrivateKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from squirrelops_home_sensor.api.deps import get_config, get_db, verify_client_cert
from squirrelops_home_sensor.secure_io import atomic_write_private_text

router = APIRouter(prefix="/pairing", tags=["pairing"])

# Setup-key and session lifecycle constants
PAIRING_PROTOCOL_VERSION = 2
CODE_EXPIRY_SECONDS = 600  # 10 minutes
MAX_FAILED_ATTEMPTS = 5
MAX_ACTIVE_SESSIONS = 32
MAX_CHALLENGES_PER_MINUTE = 10
SESSION_EXPIRY_SECONDS = 300
_SETUP_KEY_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_SETUP_KEY_CHARACTERS = 20


# ---------- Request/Response models ----------


class ChallengeResponse(BaseModel):
    protocol_version: int
    challenge_id: str
    challenge: str  # hex-encoded 32 random bytes
    sensor_id: str
    sensor_name: str


class VerifyRequest(BaseModel):
    challenge_id: str
    response: str  # hex-encoded HMAC-SHA256 over the v2 transcript
    client_nonce: str  # hex-encoded 32 random bytes
    client_name: str


class VerifyResponse(BaseModel):
    encrypted_ca_cert: str  # hex-encoded nonce + AES-GCM ciphertext
    server_nonce: str  # hex-encoded 32 random bytes


class CompleteRequest(BaseModel):
    challenge_id: str
    encrypted_csr: str  # hex-encoded nonce + AES-GCM ciphertext


class CompleteResponse(BaseModel):
    encrypted_client_cert: str  # hex-encoded nonce + AES-GCM ciphertext
    pairing_id: int


class UnpairResponse(BaseModel):
    id: int
    status: str


# ---------- Helpers ----------


def _generate_code() -> str:
    """Generate a 100-bit, human-readable setup key."""
    raw = "".join(secrets.choice(_SETUP_KEY_ALPHABET) for _ in range(_SETUP_KEY_CHARACTERS))
    return "-".join(raw[index : index + 4] for index in range(0, len(raw), 4))


def _update_code_file(ps: dict) -> None:
    """Atomically store the current setup key in the private data directory."""
    code_file = ps.get("code_file")
    if code_file is None:
        return
    try:
        atomic_write_private_text(Path(code_file), ps["code"] + "\n")
    except OSError as exc:
        logger.error("Failed to store pairing setup key: %s", exc)


def _sensor_value(config: dict, key: str, legacy_key: str, default: str) -> str:
    sensor = config.get("sensor", {})
    return str(sensor.get(key) or config.get(legacy_key) or default)


def _proof_message(challenge: bytes, client_nonce: bytes, sensor_id: str) -> bytes:
    """Build the domain-separated transcript authenticated by the setup key."""
    return (
        b"squirrelops-pairing-v2\0"
        + challenge
        + client_nonce
        + sensor_id.encode("utf-8")
    )


def _decode_hex(value: str, *, expected_length: int, field_name: str) -> bytes:
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be valid hexadecimal.",
        ) from exc
    if len(decoded) != expected_length:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} has an invalid length.",
        )
    return decoded


def _prune_pairing_state(ps: dict) -> None:
    now = time.time()
    ps["sessions"] = {
        key: value
        for key, value in ps["sessions"].items()
        if now - value["created_at"] <= SESSION_EXPIRY_SECONDS
    }
    for source, timestamps in list(ps["challenge_requests"].items()):
        recent = [timestamp for timestamp in timestamps if now - timestamp <= 60]
        if recent:
            ps["challenge_requests"][source] = recent
        else:
            del ps["challenge_requests"][source]


def _regenerate_code(ps: dict) -> None:
    ps["code"] = _generate_code()
    ps["code_created_at"] = time.time()
    ps["code_invalidated"] = False
    ps["sessions"].clear()
    _update_code_file(ps)
    logger.info("Pairing setup key regenerated")


def _generate_ca(sensor_name: str) -> tuple[EllipticCurvePrivateKey, x509.Certificate]:
    """Generate a self-signed ECDSA P-256 CA certificate."""
    ca_key = generate_private_key(SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"SquirrelOps Sensor CA ({sensor_name})"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, ca_cert


def _sign_client_cert(
    csr: x509.CertificateSigningRequest,
    ca_key: EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
) -> x509.Certificate:
    """Sign a client CSR with the CA key."""
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return client_cert


def _get_cert_fingerprint(cert: x509.Certificate) -> str:
    """Compute SHA-256 fingerprint of a certificate."""
    digest = cert.fingerprint(hashes.SHA256())
    return f"sha256:{digest.hex()}"


def _init_pairing_state(app_state, config: dict) -> dict:
    """Initialize or return existing pairing state on app.state."""
    if not hasattr(app_state, "pairing_state") or app_state.pairing_state is None:
        # Use CA from startup if available, otherwise generate (for --no-tls / tests)
        ca_key = getattr(app_state, "ca_key", None)
        ca_cert = getattr(app_state, "ca_cert", None)
        if ca_key is None or ca_cert is None:
            sensor_name = _sensor_value(config, "name", "sensor_name", "SquirrelOps")
            ca_key, ca_cert = _generate_ca(sensor_name)

        code = _generate_code()
        data_dir = config.get("sensor", {}).get("data_dir")
        app_state.pairing_state = {
            "code": code,
            "code_created_at": time.time(),
            "code_invalidated": False,
            "code_file": Path(data_dir) / "pairing-key" if data_dir else None,
            "sessions": {},
            "challenge_requests": {},
            "ca_key": ca_key,
            "ca_cert": ca_cert,
        }
        # Store code for display
        app_state.pairing_code = code
        logger.info("Pairing setup key generated")
    return app_state.pairing_state


def _maybe_regenerate_code(ps: dict) -> None:
    """Regenerate a setup key once it expires or has been consumed."""
    elapsed = time.time() - ps["code_created_at"]
    if elapsed > CODE_EXPIRY_SECONDS or ps["code_invalidated"]:
        _regenerate_code(ps)
    _prune_pairing_state(ps)


# ---------- Routes (no auth except DELETE) ----------


class LocalCodeResponse(BaseModel):
    code: str


@router.get("/local/code", response_model=LocalCodeResponse)
async def get_local_code(
    request: Request,
    config: dict = Depends(get_config),
):
    """Deprecated and disabled.

    This used to disclose the pairing code to any loopback TCP client, which let
    any local process self-pair. Loopback TCP cannot carry peer credentials, so
    local auto-pairing now happens over a peer-verified Unix socket (see
    api/local_pairing.py). Always returns 403.
    """
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Local pairing has moved to the verified pairing socket.",
    )


@router.get("/code/challenge", response_model=ChallengeResponse)
async def get_challenge(
    request: Request,
    config: dict = Depends(get_config),
):
    """Issue a random challenge for the pairing protocol. No auth required."""
    ps = _init_pairing_state(request.app.state, config)
    _maybe_regenerate_code(ps)

    source = request.client.host if request.client else "unknown"
    requests = ps["challenge_requests"].setdefault(source, [])
    if len(requests) >= MAX_CHALLENGES_PER_MINUTE:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many pairing attempts. Try again shortly.",
        )
    if len(ps["sessions"]) >= MAX_ACTIVE_SESSIONS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many active pairing sessions. Try again shortly.",
        )
    requests.append(time.time())

    challenge = os.urandom(32)
    challenge_id = secrets.token_hex(16)
    ps["sessions"][challenge_id] = {
        "challenge": challenge,
        "created_at": time.time(),
        "failed_attempts": 0,
        "shared_key": None,
        "client_name": None,
        "verified": False,
    }

    return ChallengeResponse(
        protocol_version=PAIRING_PROTOCOL_VERSION,
        challenge_id=challenge_id,
        challenge=challenge.hex(),
        sensor_id=_sensor_value(config, "id", "sensor_id", "unknown"),
        sensor_name=_sensor_value(config, "name", "sensor_name", "SquirrelOps"),
    )


@router.post("/verify", response_model=VerifyResponse)
async def verify_pairing(
    body: VerifyRequest,
    request: Request,
    config: dict = Depends(get_config),
):
    """Verify HMAC response, derive shared key, return encrypted CA cert. No auth required."""
    ps = _init_pairing_state(request.app.state, config)
    _maybe_regenerate_code(ps)

    session = ps["sessions"].get(body.challenge_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Pairing challenge is missing or expired.",
        )

    client_nonce = _decode_hex(
        body.client_nonce, expected_length=32, field_name="client_nonce"
    )
    sensor_id = _sensor_value(config, "id", "sensor_id", "unknown")
    expected = hmac_mod.new(
        ps["code"].encode("utf-8"),
        _proof_message(session["challenge"], client_nonce, sensor_id),
        hashlib.sha256,
    ).hexdigest()

    if not hmac_mod.compare_digest(body.response, expected):
        session["failed_attempts"] += 1
        if session["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
            del ps["sessions"][body.challenge_id]
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid pairing setup key.",
        )

    # The high-entropy setup key authenticates the provisional TLS channel;
    # HKDF then creates a session-specific key for certificate exchange.
    ikm = ps["code"].encode("utf-8") + session["challenge"] + client_nonce
    shared_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=sensor_id.encode("utf-8"),
        info=b"squirrelops-pairing-v2",
    ).derive(ikm)

    session["shared_key"] = shared_key
    session["client_name"] = body.client_name[:200]
    session["verified"] = True

    # Encrypt CA cert with shared key
    ca_cert_pem = ps["ca_cert"].public_bytes(serialization.Encoding.PEM)
    aesgcm = AESGCM(shared_key)
    nonce = os.urandom(12)
    encrypted_ca_cert = aesgcm.encrypt(nonce, ca_cert_pem, None)

    server_nonce = os.urandom(32)

    return VerifyResponse(
        encrypted_ca_cert=(nonce + encrypted_ca_cert).hex(),
        server_nonce=server_nonce.hex(),
    )


@router.post("/complete", response_model=CompleteResponse)
async def complete_pairing(
    body: CompleteRequest,
    request: Request,
    db: aiosqlite.Connection = Depends(get_db),
    config: dict = Depends(get_config),
):
    """Decrypt CSR, sign client cert, store pairing, return encrypted cert. No auth required."""
    ps = _init_pairing_state(request.app.state, config)
    _maybe_regenerate_code(ps)

    session = ps["sessions"].get(body.challenge_id)
    if session is None or not session.get("verified") or session.get("shared_key") is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Pairing not verified. Complete challenge/verify first.",
        )

    shared_key = session["shared_key"]

    # Decrypt CSR
    try:
        encrypted_csr_bytes = bytes.fromhex(body.encrypted_csr)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="encrypted_csr must be valid hexadecimal.",
        ) from exc
    if len(encrypted_csr_bytes) < 29:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="encrypted_csr has an invalid length.",
        )
    csr_nonce = encrypted_csr_bytes[:12]
    csr_ciphertext = encrypted_csr_bytes[12:]

    try:
        aesgcm = AESGCM(shared_key)
        csr_pem = aesgcm.decrypt(csr_nonce, csr_ciphertext, None)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to decrypt CSR.",
        )

    try:
        csr = x509.load_pem_x509_csr(csr_pem)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid CSR.",
        )
    if not csr.is_signature_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid CSR signature.",
        )

    # Sign client cert
    client_cert = _sign_client_cert(csr, ps["ca_key"], ps["ca_cert"])
    fingerprint = _get_cert_fingerprint(client_cert)

    # Store pairing record — mark as local if the request came from localhost
    now = datetime.now(UTC).isoformat()
    client_host = request.client.host if request.client else None
    is_local = 1 if client_host in ("127.0.0.1", "::1", "localhost") else 0
    cursor = await db.execute(
        """INSERT INTO pairing (client_name, client_cert_fingerprint, is_local, paired_at)
           VALUES (?, ?, ?, ?)""",
        (session["client_name"], fingerprint, is_local, now),
    )
    pairing_id = cursor.lastrowid
    await db.commit()
    if pairing_id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to store pairing.",
        )

    # Invalidate the one-time setup key and every outstanding challenge.
    ps["code_invalidated"] = True
    ps["sessions"].clear()
    code_file = ps.get("code_file")
    if code_file is not None:
        try:
            Path(code_file).unlink(missing_ok=True)
        except OSError:
            logger.warning("Failed to remove consumed pairing setup key")

    # Encrypt client cert with shared key
    client_cert_pem = client_cert.public_bytes(serialization.Encoding.PEM)
    cert_nonce = os.urandom(12)
    encrypted_client_cert = aesgcm.encrypt(cert_nonce, client_cert_pem, None)

    return CompleteResponse(
        encrypted_client_cert=(cert_nonce + encrypted_client_cert).hex(),
        pairing_id=pairing_id,
    )


# ---------- Unpair (requires auth) ----------


@router.delete("/{pairing_id}", response_model=UnpairResponse)
async def unpair(
    pairing_id: int,
    request: Request,
    db: aiosqlite.Connection = Depends(get_db),
    config: dict = Depends(get_config),
    _auth: dict = Depends(verify_client_cert),
):
    """Remove a paired client. Requires authentication."""
    cursor = await db.execute("SELECT * FROM pairing WHERE id = ?", (pairing_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pairing not found")

    await db.execute("DELETE FROM pairing WHERE id = ?", (pairing_id,))
    await db.commit()

    # Regenerate a one-time setup key and resume mDNS (runtime wiring handles mDNS).
    ps = _init_pairing_state(request.app.state, config)
    _regenerate_code(ps)

    return UnpairResponse(id=pairing_id, status="unpaired")
