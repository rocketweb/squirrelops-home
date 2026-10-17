"""Certificate issuance shared by remote and helper-mediated pairing."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID


def sign_client_cert(
    csr: x509.CertificateSigningRequest,
    ca_key: EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
) -> x509.Certificate:
    """Sign a client CSR with the sensor CA."""
    return (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )


def cert_fingerprint(cert: x509.Certificate) -> str:
    """Return the canonical SHA-256 fingerprint stored by the API."""
    return f"sha256:{cert.fingerprint(hashes.SHA256()).hex()}"
