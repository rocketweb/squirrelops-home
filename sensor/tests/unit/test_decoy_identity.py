"""Tests for durable fake-host naming and mDNS label separation."""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID

from squirrelops_home_sensor.decoys.identity import (
    canonicalize_decoy_hostname,
    canonicalize_local_hostname,
    mdns_label,
)
from squirrelops_home_sensor.decoys.tls_identity import (
    generate_host_tls_identity,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Printer", "printer"),
        ("Printer.", "printer"),
        ("Printer.local", "printer.local"),
        ("Printer.LOCAL.", "printer.local"),
        ("Printer.localdomain", "printer.localdomain"),
        ("Printer.LOCALDOMAIN.", "printer.localdomain"),
    ],
)
def test_decoy_hostname_preserves_supported_suffix(
    raw: str,
    expected: str,
) -> None:
    assert canonicalize_decoy_hostname(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["printer", "printer.local", "printer.localdomain"],
)
def test_supported_hostname_forms_share_one_mdns_label(raw: str) -> None:
    assert mdns_label(raw) == "printer"


def test_generated_hostname_remains_local() -> None:
    assert canonicalize_local_hostname("Printer") == "printer.local"


@pytest.mark.parametrize("hostname", ["server", "server.localdomain"])
def test_tls_identity_preserves_durable_hostname_and_covers_mdns(
    hostname: str,
) -> None:
    cert_pem, _key_pem = generate_host_tls_identity(
        hostname,
        "192.168.1.200",
    )
    cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == hostname
    san = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value
    assert san.get_values_for_type(x509.DNSName) == [hostname, "server.local"]


def test_local_tls_identity_does_not_duplicate_mdns_san() -> None:
    cert_pem, _key_pem = generate_host_tls_identity(
        "server.local",
        "192.168.1.200",
    )
    cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    san = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value
    assert san.get_values_for_type(x509.DNSName) == ["server.local"]


@pytest.mark.parametrize("suffix", [".local", ".localdomain"])
def test_maximum_label_tls_identity_keeps_full_name_in_san(
    suffix: str,
) -> None:
    label = "a" * 63
    hostname = f"{label}{suffix}"
    cert_pem, _key_pem = generate_host_tls_identity(
        hostname,
        "192.168.1.200",
    )
    cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == label
    san = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value
    expected_dns_names = (
        [hostname, f"{label}.local"]
        if suffix == ".localdomain"
        else [hostname]
    )
    assert san.get_values_for_type(x509.DNSName) == expected_dns_names


@pytest.mark.parametrize(
    "raw",
    ["printer.example", "printer.localdomain.example", ".local", ".localdomain"],
)
def test_decoy_hostname_rejects_other_domains(raw: str) -> None:
    with pytest.raises(ValueError):
        canonicalize_decoy_hostname(raw)
