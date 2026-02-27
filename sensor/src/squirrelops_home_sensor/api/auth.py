"""TLS client certificate authentication utilities."""
from __future__ import annotations

import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes


def get_cert_fingerprint(cert_pem: bytes) -> str:
    """Compute SHA-256 fingerprint of a PEM-encoded certificate.

    Returns a string like 'sha256:abcdef...'
    """
    cert = x509.load_pem_x509_certificate(cert_pem)
    digest = cert.fingerprint(hashes.SHA256())
    return f"sha256:{digest.hex()}"


def verify_cert_chain(client_cert_pem: bytes, ca_cert_pem: bytes) -> bool:
    """Verify that a client certificate was signed by the given CA.

    Returns True if the client cert is signed by the CA, False otherwise.
    """
    try:
        client_cert = x509.load_pem_x509_certificate(client_cert_pem)
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        # Verify the client cert's issuer matches the CA's subject
        if client_cert.issuer != ca_cert.subject:
            return False
        # Verify the signature
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            client_cert.signature,
            client_cert.tbs_certificate_bytes,
        )
        return True
    except Exception:
        return False
