"""Tests for TLS client-cert auth helpers (api/auth.py)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from squirrelops_home_sensor.api.auth import get_cert_fingerprint, verify_cert_chain


def _self_signed(cn: str) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _signed_by(ca_key, ca_cert, cn: str) -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def test_verify_cert_chain_accepts_genuinely_signed_cert():
    ca_key, ca_cert = _self_signed("Test CA")
    client = _signed_by(ca_key, ca_cert, "client")
    assert verify_cert_chain(_pem(client), _pem(ca_cert)) is True


def test_verify_cert_chain_rejects_unrelated_cert():
    _, ca_cert = _self_signed("Test CA")
    _, other = _self_signed("Impostor")
    assert verify_cert_chain(_pem(other), _pem(ca_cert)) is False


def test_get_cert_fingerprint_is_sha256_prefixed():
    _, cert = _self_signed("x")
    fp = get_cert_fingerprint(_pem(cert))
    assert fp.startswith("sha256:")
    assert len(fp) == len("sha256:") + 64
