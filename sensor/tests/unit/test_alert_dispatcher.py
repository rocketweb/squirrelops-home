"""Unit tests for alert dispatcher -- device info toggle."""

from __future__ import annotations

from squirrelops_home_sensor.alerts.dispatcher import format_slack_payload


def test_format_slack_payload_with_device_info():
    """Detailed mode includes source_mac and device_id."""
    payload = {
        "severity": "high",
        "title": "Decoy Trip",
        "alert_type": "decoy.trip",
        "source_ip": "192.168.1.50",
        "source_mac": "AA:BB:CC:DD:EE:FF",
        "device_id": 42,
        "created_at": "2026-01-01T00:00:00Z",
    }
    result = format_slack_payload(payload, include_device_info=True)
    blocks_text = str(result["blocks"])
    assert "AA:BB:CC:DD:EE:FF" in blocks_text
    assert "42" in blocks_text


def test_format_slack_payload_without_device_info():
    """Default mode excludes source_mac and device_id."""
    payload = {
        "severity": "high",
        "title": "Decoy Trip",
        "alert_type": "decoy.trip",
        "source_ip": "192.168.1.50",
        "source_mac": "AA:BB:CC:DD:EE:FF",
        "device_id": 42,
        "created_at": "2026-01-01T00:00:00Z",
    }
    result = format_slack_payload(payload, include_device_info=False)
    blocks_text = str(result["blocks"])
    assert "AA:BB:CC:DD:EE:FF" not in blocks_text
