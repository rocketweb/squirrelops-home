"""Tests for shared network input validation (SSRF + scan-target guards)."""

from __future__ import annotations

import socket
from unittest.mock import patch

from squirrelops_home_sensor.netvalidation import (
    is_safe_lan_url,
    is_safe_scan_target,
    is_valid_ipv4,
    resolve_lan_url,
)


class TestIsValidIPv4:
    def test_accepts_dotted_quad(self):
        assert is_valid_ipv4("192.168.1.5") is True

    def test_rejects_out_of_range_octet(self):
        assert is_valid_ipv4("999.1.1.1") is False

    def test_rejects_option_injection(self):
        assert is_valid_ipv4("-oG/tmp/x") is False
        assert is_valid_ipv4("--script=http-vuln") is False

    def test_rejects_hostname_and_shell_metachars(self):
        assert is_valid_ipv4("evil.example.com") is False
        assert is_valid_ipv4("192.168.1.5; rm -rf /") is False


class TestIsSafeScanTarget:
    def test_accepts_private_lan_ip(self):
        assert is_safe_scan_target("192.168.1.50") is True
        assert is_safe_scan_target("10.0.0.4") is True

    def test_rejects_public_ip(self):
        assert is_safe_scan_target("8.8.8.8") is False

    def test_rejects_link_local_metadata(self):
        assert is_safe_scan_target("169.254.169.254") is False

    def test_rejects_loopback_and_injection(self):
        assert is_safe_scan_target("127.0.0.1") is False
        assert is_safe_scan_target("-oG") is False


class TestIsSafeLanUrl:
    def test_accepts_private_http(self):
        assert is_safe_lan_url("http://192.168.1.18:1234/v1") is True

    @patch("squirrelops_home_sensor.netvalidation.socket.getaddrinfo")
    def test_accepts_dot_local_only_after_private_resolution(self, resolve):
        resolve.return_value = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("192.168.1.18", 8123),
            )
        ]
        resolved = resolve_lan_url("http://homeassistant.local:8123")
        assert resolved is not None
        assert resolved.connect_ip == "192.168.1.18"
        assert resolved.pinned_url == "http://192.168.1.18:8123"
        assert resolved.host_header == "homeassistant.local:8123"

    @patch("squirrelops_home_sensor.netvalidation.socket.getaddrinfo")
    def test_accepts_private_mdns_with_ipv6_link_local_answer(self, resolve):
        resolve.return_value = [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("fe80::aba5:d439:3458:d293", 8123, 0, 18),
            ),
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("192.168.1.58", 8123),
            ),
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("fd18:28c9:675c:2da4:1603:d581:ca4d:b143", 8123, 0, 0),
            ),
        ]

        resolved = resolve_lan_url("http://homeassistant.local:8123")

        assert resolved is not None
        assert resolved.addresses == (
            "192.168.1.58",
            "fd18:28c9:675c:2da4:1603:d581:ca4d:b143",
        )
        assert resolved.connect_ip == "192.168.1.58"

    def test_rejects_public_host(self):
        assert is_safe_lan_url("http://8.8.8.8/") is False
        assert is_safe_lan_url("https://evil.example.com/") is False

    @patch("squirrelops_home_sensor.netvalidation.socket.getaddrinfo")
    def test_rejects_dot_local_with_any_public_answer(self, resolve):
        resolve.return_value = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("192.168.1.18", 8123),
            ),
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("203.0.113.8", 8123),
            ),
        ]
        assert is_safe_lan_url("http://homeassistant.local:8123") is False

    @patch(
        "squirrelops_home_sensor.netvalidation.socket.getaddrinfo",
        side_effect=socket.gaierror("not found"),
    )
    def test_rejects_unresolved_dot_local(self, _resolve):
        assert is_safe_lan_url("http://homeassistant.local:8123") is False

    def test_rejects_metadata_and_loopback(self):
        assert is_safe_lan_url("http://169.254.169.254/latest/meta-data") is False
        assert is_safe_lan_url("http://127.0.0.1:8123") is False

    def test_rejects_non_http_scheme(self):
        assert is_safe_lan_url("ftp://192.168.1.1/") is False
        assert is_safe_lan_url("file:///etc/passwd") is False

    def test_rejects_url_credentials(self):
        assert is_safe_lan_url("http://user:pass@192.168.1.18/") is False
