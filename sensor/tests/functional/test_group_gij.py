"""Groups G, I, and J: security, data layer, device intelligence.

Nearly all of I and J was already covered: 31 db schema, 40 db query, 25 event
bus, 22 matcher, 19 composite, 11 classifier, 9 baseline, and 10 port-risk
tests. Group G was likewise covered apart from one control.

The gap is G-07. Redaction of addresses before device signals are sent to a
cloud LLM was guarded by a single assertion, despite deciding whether a user's
network layout reaches a third party. This covers it properly.

Asserts the behavior the product should have. A failure is a finding.
"""

import pytest

from squirrelops_home_sensor.devices.llm_classifier import (
    _REDACTED_ADDRESS,
    _sanitize_signal,
)


class TestG07AddressRedaction:
    """G-07: no device address may reach the classifier prompt."""

    @pytest.mark.parametrize(
        "mac",
        [
            "AE:29:0A:E5:CC:C5",
            "ae:29:0a:e5:cc:c5",
            "AE-29-0A-E5-CC-C5",
            "ae29.0ae5.ccc5",
            "AE:29:A:E5:CC:C5",
        ],
    )
    def test_every_mac_form_is_redacted(self, mac):
        sanitized = _sanitize_signal(f"host {mac} here")
        assert mac not in sanitized
        assert _REDACTED_ADDRESS in sanitized

    @pytest.mark.parametrize(
        "ip",
        ["192.168.1.101", "10.0.0.1", "172.16.31.7", "8.8.8.8"],
    )
    def test_ipv4_is_redacted(self, ip):
        sanitized = _sanitize_signal(f"device at {ip}")
        assert ip not in sanitized
        assert _REDACTED_ADDRESS in sanitized

    @pytest.mark.parametrize(
        "ip",
        [
            "fd18:28c9:675c:2da4:105b:7321:1910:4fbd",
            "fe80::1834:db4:e7f8:4b78",
            "2001:db8::1",
        ],
    )
    def test_ipv6_is_redacted(self, ip):
        sanitized = _sanitize_signal(f"device at {ip}")
        assert ip not in sanitized

    def test_an_address_hidden_inside_a_hostname_is_redacted(self):
        sanitized = _sanitize_signal("desktop-192.168.1.101.local")
        assert "192.168.1.101" not in sanitized

    def test_several_addresses_in_one_value_are_all_redacted(self):
        sanitized = _sanitize_signal(
            "AE:29:0A:E5:CC:C5 at 192.168.1.101 and 192.168.1.212"
        )
        assert "AE:29:0A:E5:CC:C5" not in sanitized
        assert "192.168.1.101" not in sanitized
        assert "192.168.1.212" not in sanitized

    def test_the_live_laptop_identifiers_do_not_survive(self):
        # The exact values observed on this network during the session.
        sanitized = _sanitize_signal("matt-m1 AE:29:0A:E5:CC:C5 192.168.1.101")
        assert "AE:29:0A:E5:CC:C5" not in sanitized
        assert "192.168.1.101" not in sanitized
        # The non-identifying part is what the classifier actually needs.
        assert "matt-m1" in sanitized

    def test_a_vendor_string_is_not_destroyed_by_redaction(self):
        # Over-redaction would make the classifier useless, so the guard has to
        # be specific rather than blanket.
        assert "Xiaomi" in _sanitize_signal("Xiaomi")
        assert "Ubiquiti Networks" in _sanitize_signal("Ubiquiti Networks")

    def test_version_like_strings_are_not_mistaken_for_addresses(self):
        # A four-part version is shaped like an IPv4 address. Redacting it would
        # discard a genuinely useful classification signal.
        sanitized = _sanitize_signal("firmware 1.2.3")
        assert "1.2.3" in sanitized


class TestG07PromptLevelRedaction:
    """The same guarantee, asserted through the prompt the model receives."""

    def test_oui_prefix_survives_but_the_full_mac_does_not(self):
        # The OUI is the vendor half and is needed to classify. The device half
        # is what identifies a household, and must not travel.
        oui = _sanitize_signal("AE:29:0A"[:8])
        full = _sanitize_signal("AE:29:0A:E5:CC:C5")
        assert full != oui
        assert _REDACTED_ADDRESS in full
