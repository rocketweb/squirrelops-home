"""Tests for TLS certificate generation and persistence."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    SECP256R1,
    generate_private_key,
)
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from squirrelops_home_sensor.tls import (
    _cert_to_pem,
    _key_to_pem,
    _pem_to_cert,
    _pem_to_key,
    ensure_tls_certs,
    generate_ca,
    generate_server_cert,
)


# ---------------------------------------------------------------------------
# In-memory SecretStore for tests
# ---------------------------------------------------------------------------


class _InMemoryStore:
    """Minimal async secret store backed by a dict."""

    def __init__(self) -> None:
        self._data: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self._data.get(key)

    async def set(self, key: str, value: str) -> None:
        self._data[key] = value

    async def delete(self, key: str) -> None:
        self._data.pop(key, None)

    async def list_keys(self) -> list[str]:
        return list(self._data.keys())


# ---------------------------------------------------------------------------
# TestGenerateCA
# ---------------------------------------------------------------------------


class TestGenerateCA:
    """Verify CA key + certificate properties."""

    def test_returns_ec_key(self) -> None:
        ca_key, _ = generate_ca("TestSensor")
        assert isinstance(ca_key, EllipticCurvePrivateKey)

    def test_returns_x509_certificate(self) -> None:
        _, ca_cert = generate_ca("TestSensor")
        assert isinstance(ca_cert, x509.Certificate)

    def test_certificate_is_ca(self) -> None:
        _, ca_cert = generate_ca("TestSensor")
        bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True
        assert bc.value.path_length == 0
        assert bc.critical is True

    def test_subject_contains_sensor_name(self) -> None:
        _, ca_cert = generate_ca("MyHomeLab")
        cn = ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "SquirrelOps Sensor CA (MyHomeLab)"

    def test_issuer_equals_subject(self) -> None:
        _, ca_cert = generate_ca("TestSensor")
        assert ca_cert.subject == ca_cert.issuer

    def test_ten_year_validity(self) -> None:
        _, ca_cert = generate_ca("TestSensor")
        delta = ca_cert.not_valid_after_utc - ca_cert.not_valid_before_utc
        # Allow a small window for execution time (3649-3650 days)
        assert 3649 <= delta.days <= 3650

    def test_public_key_matches_private_key(self) -> None:
        ca_key, ca_cert = generate_ca("TestSensor")
        assert isinstance(ca_cert.public_key(), EllipticCurvePublicKey)
        # Verify the public key embedded in the cert matches the generated key
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        cert_pub_bytes = ca_cert.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        key_pub_bytes = ca_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        assert cert_pub_bytes == key_pub_bytes


# ---------------------------------------------------------------------------
# TestGenerateServerCert
# ---------------------------------------------------------------------------


class TestGenerateServerCert:
    """Verify server certificate properties."""

    @pytest.fixture
    def ca_pair(self) -> tuple[EllipticCurvePrivateKey, x509.Certificate]:
        return generate_ca("TestSensor")

    def test_returns_ec_key(
        self, ca_pair: tuple[EllipticCurvePrivateKey, x509.Certificate]
    ) -> None:
        server_key, _ = generate_server_cert(*ca_pair)
        assert isinstance(server_key, EllipticCurvePrivateKey)

    def test_returns_x509_certificate(
        self, ca_pair: tuple[EllipticCurvePrivateKey, x509.Certificate]
    ) -> None:
        _, server_cert = generate_server_cert(*ca_pair)
        assert isinstance(server_cert, x509.Certificate)

    def test_not_a_ca(
        self, ca_pair: tuple[EllipticCurvePrivateKey, x509.Certificate]
    ) -> None:
        _, server_cert = generate_server_cert(*ca_pair)
        bc = server_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False
        assert bc.critical is True

    def test_subject_cn(
        self, ca_pair: tuple[EllipticCurvePrivateKey, x509.Certificate]
    ) -> None:
        _, server_cert = generate_server_cert(*ca_pair)
        cn = server_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "SquirrelOps Sensor"

    def test_issuer_is_ca(
        self, ca_pair: tuple[EllipticCurvePrivateKey, x509.Certificate]
    ) -> None:
        ca_key, ca_cert = ca_pair
        _, server_cert = generate_server_cert(ca_key, ca_cert)
        assert server_cert.issuer == ca_cert.subject

    def test_san_contains_localhost(
        self, ca_pair: tuple[EllipticCurvePrivateKey, x509.Certificate]
    ) -> None:
        _, server_cert = generate_server_cert(*ca_pair)
        san = server_cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "localhost" in dns_names

    def test_san_contains_ipv4_addresses(
        self, ca_pair: tuple[EllipticCurvePrivateKey, x509.Certificate]
    ) -> None:
        _, server_cert = generate_server_cert(*ca_pair)
        san = server_cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        ip_addrs = san.value.get_values_for_type(x509.IPAddress)
        assert ipaddress.IPv4Address("127.0.0.1") in ip_addrs
        assert ipaddress.IPv4Address("0.0.0.0") in ip_addrs

    def test_ten_year_validity(
        self, ca_pair: tuple[EllipticCurvePrivateKey, x509.Certificate]
    ) -> None:
        _, server_cert = generate_server_cert(*ca_pair)
        delta = server_cert.not_valid_after_utc - server_cert.not_valid_before_utc
        assert 3649 <= delta.days <= 3650

    def test_signed_by_ca(
        self, ca_pair: tuple[EllipticCurvePrivateKey, x509.Certificate]
    ) -> None:
        ca_key, ca_cert = ca_pair
        _, server_cert = generate_server_cert(ca_key, ca_cert)
        # Verify the CA public key can validate the server cert signature
        ca_cert.public_key().verify(
            server_cert.signature,
            server_cert.tbs_certificate_bytes,
            ECDSA(hashes.SHA256()),
        )

    def test_server_key_differs_from_ca_key(
        self, ca_pair: tuple[EllipticCurvePrivateKey, x509.Certificate]
    ) -> None:
        ca_key, ca_cert = ca_pair
        server_key, _ = generate_server_cert(ca_key, ca_cert)
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        server_pub = server_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        ca_pub = ca_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        assert server_pub != ca_pub


# ---------------------------------------------------------------------------
# TestEnsureTlsCerts
# ---------------------------------------------------------------------------


class TestEnsureTlsCerts:
    """Verify first-call generation + persistence and second-call loading."""

    @pytest.fixture
    def store(self) -> _InMemoryStore:
        return _InMemoryStore()

    async def test_first_call_generates_and_persists(
        self, store: _InMemoryStore, tmp_path: Path
    ) -> None:
        cert_path, key_path, ca_key, ca_cert = await ensure_tls_certs(
            store, tmp_path, "TestSensor"
        )

        # All four keys stored
        assert await store.get("tls.ca_key") is not None
        assert await store.get("tls.ca_cert") is not None
        assert await store.get("tls.server_key") is not None
        assert await store.get("tls.server_cert") is not None

    async def test_first_call_writes_pem_files(
        self, store: _InMemoryStore, tmp_path: Path
    ) -> None:
        cert_path, key_path, _, _ = await ensure_tls_certs(
            store, tmp_path, "TestSensor"
        )

        assert cert_path.exists()
        assert key_path.exists()
        assert cert_path == tmp_path / "server.crt"
        assert key_path == tmp_path / "server.key"

    async def test_pem_files_are_valid_x509(
        self, store: _InMemoryStore, tmp_path: Path
    ) -> None:
        cert_path, key_path, _, _ = await ensure_tls_certs(
            store, tmp_path, "TestSensor"
        )

        # Load and verify the PEM files parse correctly
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        assert isinstance(cert, x509.Certificate)

        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        key = load_pem_private_key(key_path.read_bytes(), password=None)
        assert isinstance(key, EllipticCurvePrivateKey)

    async def test_key_file_has_restricted_permissions(
        self, store: _InMemoryStore, tmp_path: Path
    ) -> None:
        _, key_path, _, _ = await ensure_tls_certs(store, tmp_path, "TestSensor")
        mode = key_path.stat().st_mode & 0o777
        assert mode == 0o600

    async def test_returns_ca_key_and_cert(
        self, store: _InMemoryStore, tmp_path: Path
    ) -> None:
        _, _, ca_key, ca_cert = await ensure_tls_certs(
            store, tmp_path, "TestSensor"
        )

        assert isinstance(ca_key, EllipticCurvePrivateKey)
        assert isinstance(ca_cert, x509.Certificate)
        bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True

    async def test_second_call_loads_from_store(
        self, store: _InMemoryStore, tmp_path: Path
    ) -> None:
        # First call generates
        _, _, ca_key1, ca_cert1 = await ensure_tls_certs(
            store, tmp_path, "TestSensor"
        )

        # Second call loads from store -- should get same CA
        cert_path2, key_path2, ca_key2, ca_cert2 = await ensure_tls_certs(
            store, tmp_path, "TestSensor"
        )

        # CA key should be the same (loaded from store, not regenerated)
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        assert (
            ca_key1.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            == ca_key2.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )
        # CA cert fingerprint should be the same
        assert ca_cert1.fingerprint(hashes.SHA256()) == ca_cert2.fingerprint(
            hashes.SHA256()
        )

    async def test_second_call_still_writes_pem_files(
        self, store: _InMemoryStore, tmp_path: Path
    ) -> None:
        await ensure_tls_certs(store, tmp_path, "TestSensor")

        # Delete PEM files
        (tmp_path / "server.crt").unlink()
        (tmp_path / "server.key").unlink()

        # Second call should re-create them
        cert_path, key_path, _, _ = await ensure_tls_certs(
            store, tmp_path, "TestSensor"
        )
        assert cert_path.exists()
        assert key_path.exists()

    async def test_creates_data_dir_if_missing(
        self, store: _InMemoryStore, tmp_path: Path
    ) -> None:
        nested = tmp_path / "a" / "b" / "c"
        cert_path, key_path, _, _ = await ensure_tls_certs(
            store, nested, "TestSensor"
        )
        assert nested.is_dir()
        assert cert_path.exists()

    async def test_server_cert_in_pem_file_is_signed_by_ca(
        self, store: _InMemoryStore, tmp_path: Path
    ) -> None:
        cert_path, _, _, ca_cert = await ensure_tls_certs(
            store, tmp_path, "TestSensor"
        )

        server_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        ca_cert.public_key().verify(
            server_cert.signature,
            server_cert.tbs_certificate_bytes,
            ECDSA(hashes.SHA256()),
        )


# ---------------------------------------------------------------------------
# PEM serialization round-trip
# ---------------------------------------------------------------------------


class TestPEMHelpers:
    """Verify PEM serialization helpers round-trip correctly."""

    def test_key_roundtrip(self) -> None:
        key = generate_private_key(SECP256R1())
        pem = _key_to_pem(key)
        restored = _pem_to_key(pem)
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        assert key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo) == restored.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    def test_cert_roundtrip(self) -> None:
        _, cert = generate_ca("RoundTrip")
        pem = _cert_to_pem(cert)
        restored = _pem_to_cert(pem)
        assert cert.fingerprint(hashes.SHA256()) == restored.fingerprint(hashes.SHA256())

    def test_pem_to_key_rejects_non_ec(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        ed_key = Ed25519PrivateKey.generate()
        pem = ed_key.private_bytes(
            encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.PEM,
            format=__import__("cryptography").hazmat.primitives.serialization.PrivateFormat.PKCS8,
            encryption_algorithm=__import__(
                "cryptography"
            ).hazmat.primitives.serialization.NoEncryption(),
        ).decode("utf-8")
        with pytest.raises(TypeError, match="EllipticCurvePrivateKey"):
            _pem_to_key(pem)
