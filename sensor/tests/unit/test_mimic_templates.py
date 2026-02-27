"""Tests for mimic template generation from scout profiles."""
from __future__ import annotations

import pytest

from squirrelops_home_sensor.scouts.engine import ServiceProfile
from squirrelops_home_sensor.scouts.templates import (
    MimicTemplate,
    MimicTemplateGenerator,
    _CREDENTIAL_STRATEGY,
    _MDNS_SERVICES,
)


def _make_profile(
    port: int = 80,
    device_id: int = 1,
    http_status: int | None = 200,
    http_headers: dict | None = None,
    http_body_snippet: str | None = "<html>Home</html>",
    http_server_header: str | None = "nginx/1.18",
    protocol_version: str | None = None,
) -> ServiceProfile:
    """Helper to create a ServiceProfile with sensible defaults."""
    return ServiceProfile(
        device_id=device_id,
        ip_address="192.168.1.100",
        port=port,
        http_status=http_status,
        http_headers=http_headers or {"content-type": "text/html"},
        http_body_snippet=http_body_snippet,
        http_server_header=http_server_header,
        protocol_version=protocol_version,
        scouted_at="2026-01-01T00:00:00Z",
    )


class TestMimicTemplateGenerator:
    """Verify template generation from profiles."""

    def test_empty_profiles_returns_empty_template(self) -> None:
        """No profiles should produce an empty generic template."""
        gen = MimicTemplateGenerator()
        template = gen.generate([], "unknown")
        assert template.source_device_id is None
        assert template.routes == []
        assert template.device_category == "generic"

    def test_http_profile_creates_route(self) -> None:
        """A profile with HTTP data should produce a route."""
        gen = MimicTemplateGenerator()
        profiles = [_make_profile(port=8123)]
        template = gen.generate(profiles, "smart_home", hostname="hass.local")
        assert len(template.routes) == 1
        route = template.routes[0]
        assert route["port"] == 8123
        assert route["status"] == 200
        assert route["path"] == "/"
        assert route["method"] == "GET"

    def test_non_http_profile_produces_no_routes(self) -> None:
        """A profile without HTTP data should not produce routes."""
        gen = MimicTemplateGenerator()
        profiles = [_make_profile(port=22, http_status=None, protocol_version="SSH-2.0-OpenSSH_8.9")]
        template = gen.generate(profiles, "computer")
        assert template.routes == []

    def test_server_header_picked_from_profiles(self) -> None:
        """The most common Server header should be selected."""
        gen = MimicTemplateGenerator()
        profiles = [
            _make_profile(port=80, http_server_header="nginx/1.18"),
            _make_profile(port=8080, http_server_header="nginx/1.18"),
            _make_profile(port=3000, http_server_header="gunicorn"),
        ]
        template = gen.generate(profiles, "smart_home")
        assert template.server_header == "nginx/1.18"

    def test_server_header_none_when_no_http(self) -> None:
        """No HTTP profiles means no server header."""
        gen = MimicTemplateGenerator()
        profiles = [_make_profile(port=22, http_status=None, http_server_header=None)]
        template = gen.generate(profiles, "computer")
        assert template.server_header is None

    def test_smart_home_credential_strategy(self) -> None:
        """Smart home devices should get ha_token credentials."""
        gen = MimicTemplateGenerator()
        profiles = [_make_profile()]
        template = gen.generate(profiles, "smart_home")
        assert template.credential_types == ["ha_token"]

    def test_nas_credential_strategy(self) -> None:
        """NAS devices should get password and ssh_key credentials."""
        gen = MimicTemplateGenerator()
        profiles = [_make_profile()]
        template = gen.generate(profiles, "nas")
        assert "password" in template.credential_types
        assert "ssh_key" in template.credential_types

    def test_dev_server_credential_strategy(self) -> None:
        """Computer/dev_server devices should get env_file credentials."""
        gen = MimicTemplateGenerator()
        profiles = [_make_profile()]
        template = gen.generate(profiles, "computer")
        assert template.credential_types == ["env_file"]

    def test_generic_device_gets_password(self) -> None:
        """Unknown device types should fallback to password credentials."""
        gen = MimicTemplateGenerator()
        profiles = [_make_profile()]
        template = gen.generate(profiles, "thermostat")
        assert template.credential_types == ["password"]

    def test_mdns_service_type_for_smart_home(self) -> None:
        """Smart home devices should get _home-assistant._tcp mDNS type."""
        gen = MimicTemplateGenerator()
        profiles = [_make_profile()]
        template = gen.generate(profiles, "smart_home")
        assert template.mdns_service_type == "_home-assistant._tcp"

    def test_mdns_service_type_for_printer(self) -> None:
        """Printers should get _ipp._tcp mDNS type."""
        gen = MimicTemplateGenerator()
        profiles = [_make_profile()]
        template = gen.generate(profiles, "printer")
        assert template.mdns_service_type == "_ipp._tcp"

    def test_mdns_name_from_hostname(self) -> None:
        """Template should include the hostname for mDNS name."""
        gen = MimicTemplateGenerator()
        profiles = [_make_profile()]
        template = gen.generate(profiles, "smart_home", hostname="homeassistant.local")
        assert template.mdns_name == "homeassistant.local"

    def test_ports_collected_from_profiles(self) -> None:
        """Template should track all unique ports."""
        gen = MimicTemplateGenerator()
        profiles = [
            _make_profile(port=80),
            _make_profile(port=443),
            _make_profile(port=8123),
        ]
        template = gen.generate(profiles, "smart_home")
        assert template.ports == [80, 443, 8123]

    def test_hop_by_hop_headers_stripped(self) -> None:
        """Hop-by-hop headers should be removed from routes."""
        gen = MimicTemplateGenerator()
        profiles = [_make_profile(
            port=80,
            http_headers={
                "content-type": "text/html",
                "transfer-encoding": "chunked",
                "connection": "keep-alive",
                "content-length": "1234",
            },
        )]
        template = gen.generate(profiles, "smart_home")
        assert len(template.routes) == 1
        headers = template.routes[0]["headers"]
        assert "transfer-encoding" not in headers
        assert "connection" not in headers
        assert "content-length" not in headers
        assert "content-type" in headers

    def test_source_device_id_from_first_profile(self) -> None:
        """source_device_id should come from the first profile."""
        gen = MimicTemplateGenerator()
        profiles = [_make_profile(device_id=42)]
        template = gen.generate(profiles, "smart_home")
        assert template.source_device_id == 42

    def test_source_ip_from_first_profile(self) -> None:
        """source_ip should come from the first profile."""
        gen = MimicTemplateGenerator()
        profiles = [_make_profile()]
        template = gen.generate(profiles, "smart_home")
        assert template.source_ip == "192.168.1.100"


class TestDeviceCategoryMapping:
    """Verify device type to category mapping."""

    @pytest.mark.parametrize("device_type,expected_category", [
        ("smart_home", "smart_home"),
        ("camera", "camera"),
        ("nas", "nas"),
        ("media", "media"),
        ("printer", "printer"),
        ("router", "router"),
        ("network", "router"),
        ("computer", "dev_server"),
        ("iot_widget", "generic"),
    ])
    def test_category_mapping(self, device_type: str, expected_category: str) -> None:
        """Device type should map to the correct category."""
        gen = MimicTemplateGenerator()
        profiles = [_make_profile()]
        template = gen.generate(profiles, device_type)
        assert template.device_category == expected_category
