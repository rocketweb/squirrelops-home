"""Tests for shared network input validation (SSRF + scan-target guards)."""

from __future__ import annotations

from squirrelops_home_sensor.netvalidation import (
    is_safe_lan_url,
    is_safe_scan_target,
    is_valid_ipv4,
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

    def test_accepts_dot_local(self):
        assert is_safe_lan_url("http://homeassistant.local:8123") is True

    def test_rejects_public_host(self):
        assert is_safe_lan_url("http://8.8.8.8/") is False
        assert is_safe_lan_url("https://evil.example.com/") is False

    def test_rejects_metadata_and_loopback(self):
        assert is_safe_lan_url("http://169.254.169.254/latest/meta-data") is False
        assert is_safe_lan_url("http://127.0.0.1:8123") is False

    def test_rejects_non_http_scheme(self):
        assert is_safe_lan_url("ftp://192.168.1.1/") is False
        assert is_safe_lan_url("file:///etc/passwd") is False
