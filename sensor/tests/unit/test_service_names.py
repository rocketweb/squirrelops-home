"""Tests for IANA service name lookup."""
from __future__ import annotations

from squirrelops_home_sensor.scanner.service_names import SERVICE_NAMES, get_service_name


class TestServiceNameLookup:
    """Verify service name resolution for common ports."""

    def test_well_known_ports(self) -> None:
        assert get_service_name(22) == "SSH"
        assert get_service_name(80) == "HTTP"
        assert get_service_name(443) == "HTTPS"
        assert get_service_name(53) == "DNS"

    def test_registered_ports(self) -> None:
        assert get_service_name(3306) == "MySQL"
        assert get_service_name(5432) == "PostgreSQL"
        assert get_service_name(6379) == "Redis"
        assert get_service_name(27017) == "MongoDB"

    def test_iot_ports(self) -> None:
        assert get_service_name(1883) == "MQTT"
        assert get_service_name(5683) == "CoAP"
        assert get_service_name(8123) == "Home Assistant"

    def test_unknown_port_returns_none(self) -> None:
        assert get_service_name(12345) is None
        assert get_service_name(99999) is None

    def test_mapping_has_reasonable_coverage(self) -> None:
        # Should have at least 100 entries
        assert len(SERVICE_NAMES) >= 100

    def test_all_values_are_nonempty_strings(self) -> None:
        for port, name in SERVICE_NAMES.items():
            assert isinstance(port, int), f"Port {port} is not int"
            assert isinstance(name, str) and len(name) > 0, f"Port {port} has empty name"
