"""Pairing routes: challenge-response protocol, cert exchange, unpair."""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
import logging
import os
import time
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

import aiosqlite
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, SECP256R1, generate_private_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from squirrelops_home_sensor.api.deps import get_db, get_config, verify_client_cert

router = APIRouter(prefix="/pairing", tags=["pairing"])

# Code lifecycle constants
CODE_EXPIRY_SECONDS = 600  # 10 minutes
MAX_FAILED_ATTEMPTS = 5


# ---------- Request/Response models ----------


class ChallengeResponse(BaseModel):
    challenge: str  # hex-encoded 32 random bytes
    sensor_id: str
    sensor_name: str


class VerifyRequest(BaseModel):
    response: str  # hex-encoded HMAC-SHA256(challenge, code)
    client_nonce: str  # hex-encoded 32 random bytes
    client_name: str


class VerifyResponse(BaseModel):
    encrypted_ca_cert: str  # hex-encoded nonce + AES-GCM ciphertext
    server_nonce: str  # hex-encoded 32 random bytes


class CompleteRequest(BaseModel):
    encrypted_csr: str  # hex-encoded nonce + AES-GCM ciphertext


class CompleteResponse(BaseModel):
    encrypted_client_cert: str  # hex-encoded nonce + AES-GCM ciphertext


class UnpairResponse(BaseModel):
    id: int
    status: str


# ---------- Helpers ----------


def _generate_code() -> str:
    """Generate a cryptographically random 6-digit code."""
    return f"{int.from_bytes(os.urandom(4), 'big') % 1000000:06d}"


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
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
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
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
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
            sensor_name = config.get("sensor_name", "SquirrelOps")
            ca_key, ca_cert = _generate_ca(sensor_name)

        code = _generate_code()
        app_state.pairing_state = {
            "code": code,
            "code_created_at": time.time(),
            "code_invalidated": False,
            "challenge": None,
            "failed_attempts": 0,
            "ca_key": ca_key,
            "ca_cert": ca_cert,
            "shared_key": None,
            "client_name": None,
            "verified": False,
        }
        # Store code for display
        app_state.pairing_code = code
        logger.info("Pairing code: %s", code)
    return app_state.pairing_state


def _maybe_regenerate_code(ps: dict) -> None:
    """Regenerate code if expired or max failures reached."""
    elapsed = time.time() - ps["code_created_at"]
    if elapsed > CODE_EXPIRY_SECONDS or ps["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
        ps["code"] = _generate_code()
        ps["code_created_at"] = time.time()
        ps["failed_attempts"] = 0
        ps["challenge"] = None
        ps["code_invalidated"] = False
        ps["verified"] = False
        ps["shared_key"] = None
        logger.info("Pairing code regenerated: %s", ps["code"])


# ---------- Routes (no auth except DELETE) ----------


@router.get("/code/challenge", response_model=ChallengeResponse)
async def get_challenge(
    request: Request,
    config: dict = Depends(get_config),
):
    """Issue a random challenge for the pairing protocol. No auth required."""
    ps = _init_pairing_state(request.app.state, config)
    _maybe_regenerate_code(ps)

    challenge = os.urandom(32)
    ps["challenge"] = challenge

    return ChallengeResponse(
        challenge=challenge.hex(),
        sensor_id=config.get("sensor_id", "unknown"),
        sensor_name=config.get("sensor_name", "SquirrelOps"),
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

    if ps["challenge"] is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No challenge issued. Call GET /pairing/code/challenge first.",
        )

    # Compute expected HMAC
    expected = hmac_mod.new(
        ps["code"].encode("utf-8"), ps["challenge"], hashlib.sha256
    ).hexdigest()

    if not hmac_mod.compare_digest(body.response, expected):
        ps["failed_attempts"] += 1
        _maybe_regenerate_code(ps)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid pairing code.",
        )

    # HMAC matches -- derive shared key via HKDF
    client_nonce = bytes.fromhex(body.client_nonce)
    sensor_id = config.get("sensor_id", "unknown")

    ikm = ps["code"].encode("utf-8") + ps["challenge"] + client_nonce
    shared_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=sensor_id.encode("utf-8"),
        info=b"squirrelops-pairing-v1",
    ).derive(ikm)

    ps["shared_key"] = shared_key
    ps["client_name"] = body.client_name
    ps["verified"] = True

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

    if not ps.get("verified") or ps.get("shared_key") is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Pairing not verified. Complete challenge/verify first.",
        )

    shared_key = ps["shared_key"]

    # Decrypt CSR
    encrypted_csr_bytes = bytes.fromhex(body.encrypted_csr)
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

    csr = x509.load_pem_x509_csr(csr_pem)

    # Sign client cert
    client_cert = _sign_client_cert(csr, ps["ca_key"], ps["ca_cert"])
    fingerprint = _get_cert_fingerprint(client_cert)

    # Store pairing record
    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        """INSERT INTO pairing (client_name, client_cert_fingerprint, is_local, paired_at)
           VALUES (?, ?, 0, ?)""",
        (ps["client_name"], fingerprint, now),
    )
    await db.commit()

    # Invalidate code
    ps["code_invalidated"] = True
    ps["challenge"] = None
    ps["verified"] = False
    ps["shared_key"] = None

    # Encrypt client cert with shared key
    client_cert_pem = client_cert.public_bytes(serialization.Encoding.PEM)
    cert_nonce = os.urandom(12)
    encrypted_client_cert = aesgcm.encrypt(cert_nonce, client_cert_pem, None)

    return CompleteResponse(
        encrypted_client_cert=(cert_nonce + encrypted_client_cert).hex(),
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

    # Regenerate code and resume mDNS (mDNS integration deferred to runtime wiring)
    ps = _init_pairing_state(request.app.state, config)
    ps["code"] = _generate_code()
    ps["code_created_at"] = time.time()
    ps["code_invalidated"] = False
    ps["failed_attempts"] = 0

    return UnpairResponse(id=pairing_id, status="unpaired")
