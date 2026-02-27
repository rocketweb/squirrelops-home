"""Tests for port risk evaluation against the knowledge base."""

from __future__ import annotations

import pytest

from squirrelops_home_sensor.alerts.types import Severity
from squirrelops_home_sensor.security.port_risks import evaluate_device_ports


class TestEvaluateDevicePorts:
    """Tests for evaluate_device_ports()."""

    def test_telnet_on_smart_speaker_is_high_severity(self):
        """Telnet (23) on a smart speaker should produce a HIGH severity finding."""
        findings = evaluate_device_ports(frozenset({23}), "smart_speaker")
        assert len(findings) == 1
        assert findings[0].port == 23
        assert findings[0].service_name == "Telnet"
        assert findings[0].severity == Severity.HIGH

    def test_ftp_on_any_device_is_medium_severity(self):
        """FTP (21) on any device should produce a MEDIUM severity finding."""
        findings = evaluate_device_ports(frozenset({21}), "thermostat")
        assert len(findings) == 1
        assert findings[0].port == 21
        assert findings[0].service_name == "FTP"
        assert findings[0].severity == Severity.MEDIUM

    def test_ssh_on_computer_produces_no_finding(self):
        """SSH (22) on a computer is expected and should produce no finding."""
        findings = evaluate_device_ports(frozenset({22}), "computer")
        assert len(findings) == 0

    def test_ssh_on_smart_speaker_produces_finding(self):
        """SSH (22) on a smart speaker is unexpected and should produce a finding."""
        findings = evaluate_device_ports(frozenset({22}), "smart_speaker")
        assert len(findings) == 1
        assert findings[0].port == 22
        assert findings[0].service_name == "SSH"
        assert findings[0].severity == Severity.MEDIUM

    def test_http_on_camera_without_https_produces_finding(self):
        """HTTP (80) on a camera with no HTTPS companion should flag unencrypted admin."""
        findings = evaluate_device_ports(frozenset({80}), "camera")
        assert len(findings) == 1
        assert findings[0].port == 80
        assert "Unencrypted admin" in findings[0].service_name
        assert findings[0].severity == Severity.MEDIUM

    def test_http_on_camera_with_https_produces_no_finding(self):
        """HTTP (80) on a camera with HTTPS (443) present should produce no finding."""
        findings = evaluate_device_ports(frozenset({80, 443}), "camera")
        assert len(findings) == 0

    def test_http_on_computer_produces_no_finding(self):
        """HTTP (80) on a computer is expected and should produce no finding."""
        findings = evaluate_device_ports(frozenset({80}), "computer")
        assert len(findings) == 0

    def test_empty_ports_produces_no_findings(self):
        """An empty set of ports should produce no findings."""
        findings = evaluate_device_ports(frozenset(), "smart_speaker")
        assert findings == []

    def test_multiple_risky_ports_produce_multiple_findings(self):
        """Multiple risky ports should each produce their own finding."""
        # Telnet (always risky) + FTP (always risky) + SSH (context-risky on smart_speaker)
        findings = evaluate_device_ports(frozenset({23, 21, 22}), "smart_speaker")
        found_ports = {f.port for f in findings}
        assert 23 in found_ports, "Telnet finding expected"
        assert 21 in found_ports, "FTP finding expected"
        assert 22 in found_ports, "SSH finding expected"
        assert len(findings) == 3

    def test_rdp_on_computer_no_finding_but_rdp_on_smart_home_has_finding(self):
        """RDP (3389) is expected on computers but should flag on smart_home devices."""
        computer_findings = evaluate_device_ports(frozenset({3389}), "computer")
        assert len(computer_findings) == 0

        smart_home_findings = evaluate_device_ports(frozenset({3389}), "smart_home")
        assert len(smart_home_findings) == 1
        assert smart_home_findings[0].port == 3389
        assert smart_home_findings[0].service_name == "Remote Desktop (RDP)"
        assert smart_home_findings[0].severity == Severity.HIGH
