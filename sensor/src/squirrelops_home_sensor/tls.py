"""TLS certificate generation and persistence for the sensor.

Generates an ECDSA (P-256) CA + server certificate chain on first startup,
persists them via a SecretStore, and writes PEM files for uvicorn.

The CA certificate is shared with the macOS app during pairing so the
app can pin against it.

ECDSA P-256 is used instead of Ed25519 because Apple's SecureTransport
and LibreSSL (macOS system curl) do not support Ed25519 TLS certificates.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePrivateKey, SECP256R1, generate_private_key
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PEM helpers
# ---------------------------------------------------------------------------


def _key_to_pem(key: EllipticCurvePrivateKey) -> str:
    """Serialize an EC private key to PEM (PKCS8, no encryption)."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def _cert_to_pem(cert: x509.Certificate) -> str:
    """Serialize an X.509 certificate to PEM."""
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _pem_to_key(pem: str) -> EllipticCurvePrivateKey:
    """Deserialize a PEM-encoded EC private key."""
    key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    if not isinstance(key, EllipticCurvePrivateKey):
        raise TypeError(f"Expected EllipticCurvePrivateKey, got {type(key).__name__}")
    return key


def _pem_to_cert(pem: str) -> x509.Certificate:
    """Deserialize a PEM-encoded X.509 certificate."""
    return x509.load_pem_x509_certificate(pem.encode("utf-8"))


# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------

_VALIDITY_DAYS = 3650  # ~10 years


def generate_ca(sensor_name: str) -> tuple[EllipticCurvePrivateKey, x509.Certificate]:
    """Generate a self-signed ECDSA P-256 CA certificate.

    Parameters
    ----------
    sensor_name:
        Human-readable sensor name embedded in the CA subject CN.

    Returns
    -------
    tuple of (private_key, certificate)
        The CA key pair and self-signed certificate with
        ``BasicConstraints(ca=True, path_length=0)``.
    """
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
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, ca_cert


def generate_server_cert(
    ca_key: EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
) -> tuple[EllipticCurvePrivateKey, x509.Certificate]:
    """Generate a server certificate signed by the sensor CA.

    Parameters
    ----------
    ca_key:
        The CA private key used to sign the server certificate.
    ca_cert:
        The CA certificate (its subject becomes the issuer of the server cert).

    Returns
    -------
    tuple of (private_key, certificate)
        The server key pair and CA-signed certificate with
        ``BasicConstraints(ca=False)`` and SAN entries for localhost,
        127.0.0.1, and 0.0.0.0.
    """
    server_key = generate_private_key(SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "SquirrelOps Sensor"),
    ])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(
                    __import__("ipaddress").IPv4Address("127.0.0.1")
                ),
                x509.IPAddress(
                    __import__("ipaddress").IPv4Address("0.0.0.0")
                ),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return server_key, server_cert


# ---------------------------------------------------------------------------
# Persistence / ensure
# ---------------------------------------------------------------------------

_STORE_KEYS = ("tls.ca_key", "tls.ca_cert", "tls.server_key", "tls.server_cert")


async def ensure_tls_certs(
    secret_store: object,
    data_dir: Path,
    sensor_name: str,
) -> tuple[Path, Path, EllipticCurvePrivateKey, x509.Certificate]:
    """Ensure TLS certificates exist, generating them if needed.

    On first call the function generates a fresh CA + server certificate
    chain, persists the PEM-encoded material into *secret_store*, and
    writes the server certificate and key to disk for uvicorn.

    On subsequent calls it loads the persisted material from the store
    and re-writes the PEM files (they may have been cleared on restart).

    Parameters
    ----------
    secret_store:
        An object implementing ``async get(key) -> str | None`` and
        ``async set(key, value) -> None``.
    data_dir:
        Directory where ``server.crt`` and ``server.key`` will be written.
    sensor_name:
        Human-readable sensor name for the CA subject CN.

    Returns
    -------
    tuple of (cert_path, key_path, ca_key, ca_cert)
    """
    store = secret_store  # duck-typed SecretStore

    existing_ca_key_pem = await store.get("tls.ca_key")  # type: ignore[union-attr]

    if existing_ca_key_pem is not None:
        logger.info("Loading existing TLS certificates from secret store")
        ca_key = _pem_to_key(existing_ca_key_pem)
        ca_cert = _pem_to_cert(await store.get("tls.ca_cert"))  # type: ignore[arg-type]
        server_key = _pem_to_key(await store.get("tls.server_key"))  # type: ignore[arg-type]
        server_cert = _pem_to_cert(await store.get("tls.server_cert"))  # type: ignore[arg-type]
    else:
        logger.info("Generating new TLS certificate chain for sensor %r", sensor_name)
        ca_key, ca_cert = generate_ca(sensor_name)
        server_key, server_cert = generate_server_cert(ca_key, ca_cert)

        await store.set("tls.ca_key", _key_to_pem(ca_key))  # type: ignore[union-attr]
        await store.set("tls.ca_cert", _cert_to_pem(ca_cert))  # type: ignore[union-attr]
        await store.set("tls.server_key", _key_to_pem(server_key))  # type: ignore[union-attr]
        await store.set("tls.server_cert", _cert_to_pem(server_cert))  # type: ignore[union-attr]

    # Always write PEM files for uvicorn
    cert_path = data_dir / "server.crt"
    key_path = data_dir / "server.key"

    data_dir.mkdir(parents=True, exist_ok=True)
    cert_path.write_text(_cert_to_pem(server_cert))
    key_path.write_text(_key_to_pem(server_key))
    # Restrict key file permissions
    key_path.chmod(0o600)

    logger.info("TLS PEM files written to %s", data_dir)
    return cert_path, key_path, ca_key, ca_cert
