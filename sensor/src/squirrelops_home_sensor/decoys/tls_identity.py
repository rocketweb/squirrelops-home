"""Self-signed TLS identity generation for virtual mimic hosts."""

from __future__ import annotations

import ipaddress
import os
import ssl
import tempfile
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from squirrelops_home_sensor.decoys.identity import canonicalize_local_hostname


def generate_host_tls_identity(
    hostname: str,
    bind_address: str,
) -> tuple[str, str]:
    """Generate a stable-persistable certificate/key pair for one fake host."""
    canonical = canonicalize_local_hostname(hostname)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, canonical)]
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(canonical),
                    x509.IPAddress(ipaddress.ip_address(bind_address)),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    return cert_pem, key_pem


def server_ssl_context(cert_pem: str, key_pem: str) -> ssl.SSLContext:
    """Load an in-memory persisted identity into a server SSL context."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert_path = ""
    key_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="ascii",
            prefix="squirrelops-mimic-cert-",
            suffix=".pem",
            delete=False,
        ) as cert_file:
            cert_file.write(cert_pem)
            cert_path = cert_file.name
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="ascii",
            prefix="squirrelops-mimic-key-",
            suffix=".pem",
            delete=False,
        ) as key_file:
            key_file.write(key_pem)
            key_path = key_file.name
        os.chmod(cert_path, 0o600)
        os.chmod(key_path, 0o600)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        return context
    finally:
        for path in (cert_path, key_path):
            if path:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
