"""Unit tests for alert type definitions and severity mapping."""

import pytest


class TestSeverityEnum:
    """Severity enum has correct ordering: CRITICAL > HIGH > MEDIUM > LOW."""

    def test_severity_values_exist(self):
        from squirrelops_home_sensor.alerts.types import Severity

        assert Severity.CRITICAL is not None
        assert Severity.HIGH is not None
        assert Severity.MEDIUM is not None
        assert Severity.LOW is not None

    def test_severity_ordering_critical_gt_high(self):
        from squirrelops_home_sensor.alerts.types import Severity

        assert Severity.CRITICAL > Severity.HIGH

    def test_severity_ordering_high_gt_medium(self):
        from squirrelops_home_sensor.alerts.types import Severity

        assert Severity.HIGH > Severity.MEDIUM

    def test_severity_ordering_medium_gt_low(self):
        from squirrelops_home_sensor.alerts.types import Severity

        assert Severity.MEDIUM > Severity.LOW

    def test_severity_ordering_critical_gt_low(self):
        from squirrelops_home_sensor.alerts.types import Severity

        assert Severity.CRITICAL > Severity.LOW

    def test_severity_max_returns_highest(self):
        from squirrelops_home_sensor.alerts.types import Severity

        assert max(Severity.LOW, Severity.CRITICAL) == Severity.CRITICAL
        assert max(Severity.MEDIUM, Severity.HIGH) == Severity.HIGH

    def test_severity_min_returns_lowest(self):
        from squirrelops_home_sensor.alerts.types import Severity

        assert min(Severity.LOW, Severity.CRITICAL) == Severity.LOW
        assert min(Severity.MEDIUM, Severity.HIGH) == Severity.MEDIUM

    def test_severity_sort_descending(self):
        from squirrelops_home_sensor.alerts.types import Severity

        severities = [Severity.LOW, Severity.CRITICAL, Severity.MEDIUM, Severity.HIGH]
        sorted_desc = sorted(severities, reverse=True)
        assert sorted_desc == [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ]

    def test_severity_string_value(self):
        from squirrelops_home_sensor.alerts.types import Severity

        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"

    def test_severity_from_string(self):
        from squirrelops_home_sensor.alerts.types import Severity

        assert Severity("critical") == Severity.CRITICAL
        assert Severity("high") == Severity.HIGH
        assert Severity("medium") == Severity.MEDIUM
        assert Severity("low") == Severity.LOW

    def test_severity_invalid_string_raises(self):
        from squirrelops_home_sensor.alerts.types import Severity

        with pytest.raises(ValueError):
            Severity("unknown")


class TestAlertTypeEnum:
    """AlertType enum has all required types."""

    def test_decoy_credential_trip_exists(self):
        from squirrelops_home_sensor.alerts.types import AlertType

        assert AlertType.DECOY_CREDENTIAL_TRIP.value == "decoy.credential_trip"

    def test_decoy_trip_exists(self):
        from squirrelops_home_sensor.alerts.types import AlertType

        assert AlertType.DECOY_TRIP.value == "decoy.trip"

    def test_device_new_exists(self):
        from squirrelops_home_sensor.alerts.types import AlertType

        assert AlertType.DEVICE_NEW.value == "device.new"

    def test_device_verification_needed_exists(self):
        from squirrelops_home_sensor.alerts.types import AlertType

        assert AlertType.DEVICE_VERIFICATION_NEEDED.value == "device.verification_needed"

    def test_device_mac_changed_exists(self):
        from squirrelops_home_sensor.alerts.types import AlertType

        assert AlertType.DEVICE_MAC_CHANGED.value == "device.mac_changed"

    def test_system_sensor_offline_exists(self):
        from squirrelops_home_sensor.alerts.types import AlertType

        assert AlertType.SYSTEM_SENSOR_OFFLINE.value == "system.sensor_offline"

    def test_system_learning_complete_exists(self):
        from squirrelops_home_sensor.alerts.types import AlertType

        assert AlertType.SYSTEM_LEARNING_COMPLETE.value == "system.learning_complete"


class TestAlertSeverityMapping:
    """Each alert type maps to the correct severity."""

    def test_decoy_credential_trip_is_critical(self):
        from squirrelops_home_sensor.alerts.types import (
            AlertType,
            Severity,
            severity_for_alert_type,
        )

        assert severity_for_alert_type(AlertType.DECOY_CREDENTIAL_TRIP) == Severity.CRITICAL

    def test_decoy_trip_is_high(self):
        from squirrelops_home_sensor.alerts.types import (
            AlertType,
            Severity,
            severity_for_alert_type,
        )

        assert severity_for_alert_type(AlertType.DECOY_TRIP) == Severity.HIGH

    def test_device_new_is_medium(self):
        from squirrelops_home_sensor.alerts.types import (
            AlertType,
            Severity,
            severity_for_alert_type,
        )

        assert severity_for_alert_type(AlertType.DEVICE_NEW) == Severity.MEDIUM

    def test_device_verification_needed_is_medium(self):
        from squirrelops_home_sensor.alerts.types import (
            AlertType,
            Severity,
            severity_for_alert_type,
        )

        assert severity_for_alert_type(AlertType.DEVICE_VERIFICATION_NEEDED) == Severity.MEDIUM

    def test_device_mac_changed_is_high(self):
        from squirrelops_home_sensor.alerts.types import (
            AlertType,
            Severity,
            severity_for_alert_type,
        )

        assert severity_for_alert_type(AlertType.DEVICE_MAC_CHANGED) == Severity.HIGH

    def test_system_sensor_offline_is_low(self):
        from squirrelops_home_sensor.alerts.types import (
            AlertType,
            Severity,
            severity_for_alert_type,
        )

        assert severity_for_alert_type(AlertType.SYSTEM_SENSOR_OFFLINE) == Severity.LOW

    def test_system_learning_complete_is_low(self):
        from squirrelops_home_sensor.alerts.types import (
            AlertType,
            Severity,
            severity_for_alert_type,
        )

        assert severity_for_alert_type(AlertType.SYSTEM_LEARNING_COMPLETE) == Severity.LOW


class TestAlertTypeHelpers:
    """Helper functions for alert type metadata."""

    def test_is_decoy_alert(self):
        from squirrelops_home_sensor.alerts.types import AlertType, is_decoy_alert

        assert is_decoy_alert(AlertType.DECOY_TRIP) is True
        assert is_decoy_alert(AlertType.DECOY_CREDENTIAL_TRIP) is True
        assert is_decoy_alert(AlertType.DEVICE_NEW) is False
        assert is_decoy_alert(AlertType.SYSTEM_SENSOR_OFFLINE) is False

    def test_is_device_alert(self):
        from squirrelops_home_sensor.alerts.types import AlertType, is_device_alert

        assert is_device_alert(AlertType.DEVICE_NEW) is True
        assert is_device_alert(AlertType.DEVICE_VERIFICATION_NEEDED) is True
        assert is_device_alert(AlertType.DEVICE_MAC_CHANGED) is True
        assert is_device_alert(AlertType.DECOY_TRIP) is False

    def test_is_system_alert(self):
        from squirrelops_home_sensor.alerts.types import AlertType, is_system_alert

        assert is_system_alert(AlertType.SYSTEM_SENSOR_OFFLINE) is True
        assert is_system_alert(AlertType.SYSTEM_LEARNING_COMPLETE) is True
        assert is_system_alert(AlertType.DECOY_TRIP) is False

    def test_severity_emoji(self):
        from squirrelops_home_sensor.alerts.types import Severity, severity_emoji

        assert severity_emoji(Severity.CRITICAL) == "\U0001f534"  # red circle
        assert severity_emoji(Severity.HIGH) == "\U0001f7e0"  # orange circle
        assert severity_emoji(Severity.MEDIUM) == "\U0001f7e1"  # yellow circle
        assert severity_emoji(Severity.LOW) == "\U0001f535"  # blue circle

    def test_all_alert_types_have_severity(self):
        """Every defined AlertType must have a severity mapping."""
        from squirrelops_home_sensor.alerts.types import (
            AlertType,
            severity_for_alert_type,
        )

        for alert_type in AlertType:
            severity = severity_for_alert_type(alert_type)
            assert severity is not None, f"{alert_type} has no severity mapping"
