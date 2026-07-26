"""Tests for mimic mDNS hostname generation and advertiser."""

from __future__ import annotations

import re
from unittest.mock import AsyncMock

import pytest

from squirrelops_home_sensor.scouts.mdns import (
    MimicMDNSAdvertiser,
    generate_mimic_hostname,
    mdns_service_type_for,
    mimic_display_name,
    network_uses_host_identifiers,
    should_refresh_mimic_name,
)


class TestGenerateMimicHostname:
    """Tests for generate_mimic_hostname()."""

    def test_deterministic_for_same_ip(self):
        """Same virtual IP always produces the same hostname."""
        h1 = generate_mimic_hostname(None, "smart_home", "192.168.1.200")
        h2 = generate_mimic_hostname(None, "smart_home", "192.168.1.200")
        assert h1 == h2

    def test_source_name_informs_style_without_being_cloned(self):
        """A fake host never advertises a numbered clone of its source."""
        h = generate_mimic_hostname("tp-link-plug", "smart_home", "192.168.1.200")
        assert not h.startswith("tp-link-plug-")
        assert h in {"home", "hub", "control", "automation"}

    def test_strips_local_suffix(self):
        """Generated names do not carry .local or random suffixes."""
        h = generate_mimic_hostname("my-device.local.", "generic", "192.168.1.200")
        assert ".local" not in h
        assert not re.search(r"-(?:\d+|[0-9a-f]{4})$", h)

    def test_category_prefix_for_smart_home(self):
        """Smart home category uses plausible generic names."""
        h = generate_mimic_hostname(None, "smart_home", "192.168.1.200")
        assert h in {"home", "hub", "control", "automation"}

    def test_category_prefix_for_camera(self):
        """Camera category uses plausible generic names."""
        h = generate_mimic_hostname(None, "camera", "192.168.1.200")
        assert h in {
            "camera", "security", "garage-cam", "porch-cam",
        }

    def test_unknown_category_falls_back_to_generic(self):
        """Unknown device category uses generic bait names."""
        h = generate_mimic_hostname(None, "unknown_type", "192.168.1.200")
        assert h in {
            "files", "media", "business", "office", "docs", "backup",
        }

    @pytest.mark.parametrize("category", ["nas", "printer", "generic"])
    def test_full_profile_names_are_unique_without_generic_identifiers(self, category):
        names: set[str] = set()
        for octet in range(200, 210):
            name = generate_mimic_hostname(
                None,
                category,
                f"192.168.1.{octet}",
                existing_hostnames=names,
            )
            names.add(name)
        assert len(names) == 10
        assert all(not re.search(r"-(?:\d+|[0-9a-f]{4})$", name) for name in names)

    def test_ai_suggestion_is_preferred_after_local_validation(self):
        assert generate_mimic_hostname(
            None,
            "nas",
            "192.168.1.200",
            existing_hostnames={"files", "media"},
            suggested_names=["starbase-files"],
        ) == "starbase-files"

    def test_ai_collision_falls_back_to_generic_name(self):
        name = generate_mimic_hostname(
            None,
            "nas",
            "192.168.1.200",
            existing_hostnames={"starbase-files"},
            suggested_names=["starbase-files"],
        )
        assert name != "starbase-files"
        assert name in {"files", "backup", "archive", "storage"}

    def test_ai_identifier_is_rejected_when_network_has_no_identifier_pattern(self):
        name = generate_mimic_hostname(
            None,
            "nas",
            "192.168.1.200",
            existing_hostnames={"media", "office"},
            suggested_names=["starbase-2042", "files-a6d6"],
            allow_identifiers=False,
        )
        assert name not in {"starbase-2042", "files-a6d6"}

    def test_network_identifier_detection_requires_a_pattern(self):
        assert network_uses_host_identifiers(
            ["office-01.local", "office-02.local", "media"]
        )
        assert not network_uses_host_identifiers(
            ["iphone-15-pro.local", "media", "files", "office"]
        )

    def test_mimic_display_name_adds_local_suffix(self):
        """Decoy display names match the advertised local hostname."""
        assert mimic_display_name("files") == "files.local"
        assert mimic_display_name("media.local.") == "media.local"

    def test_refreshes_legacy_mimic_names(self):
        """Old generated mimic names are backfilled at restart."""
        assert should_refresh_mimic_name("Mimic: mattbook", "mattbook-A1B2") is True
        assert should_refresh_mimic_name("files.local", "files") is False


class TestMimicMDNSAdvertiser:
    """Tests for MimicMDNSAdvertiser lifecycle."""

    @pytest.mark.asyncio
    async def test_register_without_start_returns_false(self):
        """Register before start() returns False."""
        adv = MimicMDNSAdvertiser()
        result = await adv.register(
            decoy_id=1,
            virtual_ip="192.168.1.200",
            port=80,
            service_type="_http._tcp",
            hostname="test-device-ABCD",
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_unregister_without_services_is_noop(self):
        """Unregistering a non-existent decoy is a no-op."""
        adv = MimicMDNSAdvertiser()
        await adv.unregister(999)  # Should not raise

    @pytest.mark.asyncio
    async def test_stop_without_start_is_noop(self):
        """Stopping before start() is a no-op."""
        adv = MimicMDNSAdvertiser()
        await adv.stop()  # Should not raise

    @pytest.mark.asyncio
    async def test_same_category_mimics_register_unique_service_instances(self):
        adv = MimicMDNSAdvertiser()
        zeroconf = AsyncMock()
        adv._zeroconf = zeroconf
        existing: set[str] = set()

        for decoy_id, octet in enumerate((200, 204), start=1):
            ip = f"192.168.1.{octet}"
            hostname = generate_mimic_hostname(
                None,
                "nas",
                ip,
                existing_hostnames=existing,
            )
            existing.add(hostname)
            assert await adv.register(
                decoy_id=decoy_id,
                virtual_ip=ip,
                port=445,
                service_type="_smb._tcp",
                hostname=hostname,
            )

        service_names = {
            call.args[0].name
            for call in zeroconf.async_register_service.await_args_list
        }
        assert len(service_names) == 2


class TestMDNSServiceType:
    def test_generic_cups_port_is_not_advertised_as_a_printer(self):
        assert mdns_service_type_for(
            port=631,
            service_name="IPP/CUPS",
            configured_type=None,
        ) is None

    def test_printer_profile_advertises_ipp(self):
        assert mdns_service_type_for(
            port=631,
            service_name="IPP/CUPS",
            configured_type="_ipp._tcp",
        ) == "_ipp._tcp"

    def test_connect_safe_services_still_map_by_port(self):
        assert mdns_service_type_for(
            port=445,
            service_name="SMB",
            configured_type=None,
        ) == "_smb._tcp"
