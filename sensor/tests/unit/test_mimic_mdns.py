"""Tests for mimic mDNS hostname generation and advertiser."""

from __future__ import annotations

import pytest

from squirrelops_home_sensor.scouts.mdns import (
    MimicMDNSAdvertiser,
    generate_mimic_hostname,
)


class TestGenerateMimicHostname:
    """Tests for generate_mimic_hostname()."""

    def test_deterministic_for_same_ip(self):
        """Same virtual IP always produces the same hostname."""
        h1 = generate_mimic_hostname(None, "smart_home", "192.168.1.200")
        h2 = generate_mimic_hostname(None, "smart_home", "192.168.1.200")
        assert h1 == h2

    def test_different_ips_give_different_hostnames(self):
        """Different IPs produce different hostnames."""
        h1 = generate_mimic_hostname(None, "smart_home", "192.168.1.200")
        h2 = generate_mimic_hostname(None, "smart_home", "192.168.1.201")
        assert h1 != h2

    def test_uses_mdns_name_as_base(self):
        """When mdns_name is provided, it's used as the base."""
        h = generate_mimic_hostname("tp-link-plug", "smart_home", "192.168.1.200")
        assert h.startswith("tp-link-plug-")

    def test_strips_local_suffix(self):
        """Strips .local. suffix from mdns_name."""
        h = generate_mimic_hostname("my-device.local.", "generic", "192.168.1.200")
        assert ".local" not in h
        assert h.startswith("my-device-")

    def test_category_prefix_for_smart_home(self):
        """Smart home category uses appropriate prefixes."""
        h = generate_mimic_hostname(None, "smart_home", "192.168.1.200")
        valid_prefixes = ["tapo-plug", "kasa-smart", "wemo-mini", "hue-bridge", "tp-smart"]
        assert any(h.startswith(p) for p in valid_prefixes)

    def test_category_prefix_for_camera(self):
        """Camera category uses appropriate prefixes."""
        h = generate_mimic_hostname(None, "camera", "192.168.1.200")
        valid_prefixes = ["ipcam", "wyze-cam", "reolink-cam", "blink-mini"]
        assert any(h.startswith(p) for p in valid_prefixes)

    def test_unknown_category_falls_back_to_generic(self):
        """Unknown device category uses generic prefixes."""
        h = generate_mimic_hostname(None, "unknown_type", "192.168.1.200")
        valid_prefixes = ["iot-device", "smart-device"]
        assert any(h.startswith(p) for p in valid_prefixes)

    def test_hostname_has_suffix(self):
        """All hostnames have a 4-char hex suffix."""
        h = generate_mimic_hostname(None, "nas", "192.168.1.200")
        suffix = h.split("-")[-1]
        assert len(suffix) == 4
        assert all(c in "0123456789ABCDEF" for c in suffix)


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
