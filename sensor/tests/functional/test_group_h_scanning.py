"""Group H: scanning and discovery.

Most of Group H turned out to be covered already, by 134 existing tests across
test_scan_loop.py (64), test_ssdp_scanner.py (17), test_mdns.py (22),
test_port_scanner_banners.py (14), test_port_scanner.py (9), and
test_mdns_browser.py (8). See qa/FINDINGS.md for the mapping.

Only the genuinely uncovered cases live here.

Asserts the behavior the product should have. A failure is a finding.
"""

import pytest

from squirrelops_home_sensor.fingerprint.signals import normalize_mac


class TestH03UnpaddedArpOctets:
    """H-03: macOS `arp -an` omits the leading zero in an octet.

    A previously fixed defect in this project. It was not covered by
    test_signals.py, which tests nine other input shapes but never the
    zero-padding case, so nothing would catch a regression.
    """

    def test_a_single_unpadded_octet_is_padded(self):
        assert normalize_mac("ae:29:a:e5:cc:c5") == "AE:29:0A:E5:CC:C5"

    def test_every_octet_may_be_unpadded(self):
        assert normalize_mac("a:b:c:d:e:f") == "0A:0B:0C:0D:0E:0F"

    def test_mixed_padded_and_unpadded(self):
        assert normalize_mac("0:1a:b:2c:d:3e") == "00:1A:0B:2C:0D:3E"

    def test_the_live_laptop_address_round_trips(self):
        # The exact form observed from `arp -an` on this machine.
        assert normalize_mac("ae:29:a:e5:cc:c5") == normalize_mac(
            "AE:29:0A:E5:CC:C5"
        )

    def test_an_over_long_octet_is_still_rejected(self):
        with pytest.raises(ValueError, match="Invalid MAC"):
            normalize_mac("aaa:bb:cc:dd:ee:ff")


class TestH05SensorOwnMacsExcluded:
    """H-05: the sensor must not report itself as an ARP identity conflict."""

    def test_local_interface_macs_are_discovered(self):
        from squirrelops_home_sensor.scanner.loop import _local_interface_macs

        macs = _local_interface_macs()
        assert isinstance(macs, set)
        # Every entry must already be normalized, or comparison against scan
        # results silently fails to match and the sensor flags itself.
        for mac in macs:
            assert mac == normalize_mac(mac), f"{mac} is not normalized"
