"""Tests for mimic mDNS hostname generation and advertiser."""

from __future__ import annotations

import pytest

from squirrelops_home_sensor.scouts.mdns import (
    MimicMDNSAdvertiser,
    generate_mimic_hostname,
    mimic_display_name,
    should_refresh_mimic_name,
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
        """Source device names are not copied into bait hostnames."""
        h = generate_mimic_hostname("tp-link-plug", "smart_home", "192.168.1.200")
        assert h in {"home", "hub", "control", "automation"}
        assert "tp-link" not in h

    def test_strips_local_suffix(self):
        """Generated names do not carry .local or random suffixes."""
        h = generate_mimic_hostname("my-device.local.", "generic", "192.168.1.200")
        assert ".local" not in h
        assert h in {"files", "media", "business", "office", "docs", "backup"}

    def test_category_prefix_for_smart_home(self):
        """Smart home category uses plausible generic names."""
        h = generate_mimic_hostname(None, "smart_home", "192.168.1.200")
        assert h in {"home", "hub", "control", "automation"}

    def test_category_prefix_for_camera(self):
        """Camera category uses plausible generic names."""
        h = generate_mimic_hostname(None, "camera", "192.168.1.200")
        assert h in {"camera", "security", "garage-cam", "porch-cam"}

    def test_unknown_category_falls_back_to_generic(self):
        """Unknown device category uses generic bait names."""
        h = generate_mimic_hostname(None, "unknown_type", "192.168.1.200")
        assert h in {"files", "media", "business", "office", "docs", "backup"}

    def test_hostname_has_no_random_suffix(self):
        """Hostnames look human-created, not generated."""
        h = generate_mimic_hostname(None, "nas", "192.168.1.200")
        assert h in {"files", "backup", "archive", "storage"}
        assert not h[-4:].isalnum() or "-" not in h

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
