"""Tests for config secret redaction and write-back preservation."""

import pytest

from squirrelops_home_sensor.api.config_secrets import (
    ALERT_METHOD_SECRET_PATHS,
    CONFIG_SECRET_PATHS,
    REDACTED,
    redact,
    redact_alert_methods,
    redact_config,
    restore,
    restore_alert_method_secrets,
    restore_config_secrets,
)


def _config() -> dict:
    return {
        "sensor": {"name": "s", "secret_passphrase": "hunter2"},
        "classifier": {"mode": "local_llm", "llm_api_key": "fw-abc123"},
        "home_assistant": {"enabled": True, "url": "http://ha.local", "token": "eyJhbG"},
        "alert_methods": {
            "slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/services/X/Y/Z"},
            "push": {
                "enabled": True,
                "relay_url": "https://push.example/relay",
                "relay_token": "relay-secret",
                "device_token": "device-secret",
            },
            "log": {"enabled": True},
        },
        "network": {"scan_interval": 60},
    }


class TestRedactConfig:
    def test_replaces_every_known_secret(self) -> None:
        out = redact_config(_config())
        assert out["sensor"]["secret_passphrase"] == REDACTED
        assert out["classifier"]["llm_api_key"] == REDACTED
        assert out["home_assistant"]["token"] == REDACTED
        assert out["alert_methods"]["slack"]["webhook_url"] == REDACTED
        assert out["alert_methods"]["push"]["relay_token"] == REDACTED
        assert out["alert_methods"]["push"]["device_token"] == REDACTED

    def test_leaves_non_secret_values_intact(self) -> None:
        out = redact_config(_config())
        assert out["network"]["scan_interval"] == 60
        assert out["home_assistant"]["url"] == "http://ha.local"
        assert out["alert_methods"]["slack"]["enabled"] is True
        assert out["alert_methods"]["push"]["relay_url"] == "https://push.example/relay"
        assert out["alert_methods"]["log"] == {"enabled": True}

    def test_does_not_mutate_the_live_config(self) -> None:
        cfg = _config()
        redact_config(cfg)
        assert cfg["home_assistant"]["token"] == "eyJhbG"
        assert cfg["alert_methods"]["slack"]["webhook_url"].startswith("https://")

    @pytest.mark.parametrize("empty", [None, ""])
    def test_unset_secrets_stay_unset(self, empty) -> None:
        cfg = _config()
        cfg["home_assistant"]["token"] = empty
        cfg["classifier"]["llm_api_key"] = empty
        out = redact_config(cfg)
        assert out["home_assistant"]["token"] == empty
        assert out["classifier"]["llm_api_key"] == empty

    def test_redacts_every_alert_method_not_just_slack(self) -> None:
        cfg = _config()
        cfg["alert_methods"]["teams"] = {"webhook_url": "https://outlook.office.com/hook"}
        out = redact_config(cfg)
        assert out["alert_methods"]["teams"]["webhook_url"] == REDACTED

    def test_unknown_alert_method_fields_fail_closed(self) -> None:
        cfg = _config()
        cfg["alert_methods"]["smtp"] = {
            "enabled": True,
            "smtp_password": "future-secret",
        }
        out = redact_config(cfg)
        assert out["alert_methods"]["smtp"]["enabled"] is True
        assert out["alert_methods"]["smtp"]["smtp_password"] == REDACTED

    def test_tolerates_missing_and_malformed_sections(self) -> None:
        assert redact({}, CONFIG_SECRET_PATHS) == {}
        assert redact({"home_assistant": None}, CONFIG_SECRET_PATHS) == {"home_assistant": None}
        assert redact({"alert_methods": []}, CONFIG_SECRET_PATHS) == {"alert_methods": []}
        assert redact(
            {"alert_methods": {"slack": "nope"}}, CONFIG_SECRET_PATHS
        ) == {"alert_methods": {"slack": "nope"}}

    def test_non_string_secret_is_still_redacted(self) -> None:
        out = redact({"home_assistant": {"token": 12345}}, CONFIG_SECRET_PATHS)
        assert out["home_assistant"]["token"] == REDACTED


class TestRestoreConfigSecrets:
    def test_sentinel_is_replaced_by_the_stored_secret(self) -> None:
        stored = _config()
        incoming = {"home_assistant": {"enabled": False, "token": REDACTED}}
        out = restore_config_secrets(incoming, stored)
        assert out["home_assistant"]["token"] == "eyJhbG"
        assert out["home_assistant"]["enabled"] is False

    def test_a_real_new_value_overwrites_the_stored_secret(self) -> None:
        stored = _config()
        incoming = {"home_assistant": {"token": "eyJnew"}}
        out = restore_config_secrets(incoming, stored)
        assert out["home_assistant"]["token"] == "eyJnew"

    def test_empty_string_clears_the_secret(self) -> None:
        stored = _config()
        incoming = {"home_assistant": {"token": ""}}
        out = restore_config_secrets(incoming, stored)
        assert out["home_assistant"]["token"] == ""

    def test_sentinel_with_no_stored_secret_is_dropped_not_persisted(self) -> None:
        stored = {"home_assistant": {"enabled": True}}
        incoming = {"home_assistant": {"token": REDACTED}}
        out = restore_config_secrets(incoming, stored)
        assert "token" not in out["home_assistant"]

    def test_does_not_mutate_its_inputs(self) -> None:
        stored = _config()
        incoming = {"home_assistant": {"token": REDACTED}}
        restore_config_secrets(incoming, stored)
        assert incoming["home_assistant"]["token"] == REDACTED
        assert stored["home_assistant"]["token"] == "eyJhbG"

    def test_restores_per_alert_method_independently(self) -> None:
        stored = _config()
        stored["alert_methods"]["teams"] = {"webhook_url": "https://teams.example/hook"}
        incoming = {
            "alert_methods": {
                "slack": {"enabled": False, "webhook_url": REDACTED},
                "teams": {"webhook_url": "https://teams.example/new"},
            }
        }
        out = restore_config_secrets(incoming, stored)
        assert out["alert_methods"]["slack"]["webhook_url"].endswith("/X/Y/Z")
        assert out["alert_methods"]["teams"]["webhook_url"].endswith("/new")

    def test_restores_push_tokens_and_future_secret_fields(self) -> None:
        stored = _config()
        stored["alert_methods"]["push"]["smtp_password"] = "future-secret"
        incoming = {
            "alert_methods": {
                "push": {
                    "relay_token": REDACTED,
                    "device_token": REDACTED,
                    "smtp_password": REDACTED,
                }
            }
        }
        out = restore_config_secrets(incoming, stored)
        assert out["alert_methods"]["push"]["relay_token"] == "relay-secret"
        assert out["alert_methods"]["push"]["device_token"] == "device-secret"
        assert out["alert_methods"]["push"]["smtp_password"] == "future-secret"

    def test_tolerates_missing_stored_sections(self) -> None:
        out = restore({"home_assistant": {"token": REDACTED}}, {}, CONFIG_SECRET_PATHS)
        assert "token" not in out["home_assistant"]


class TestAlertMethodSubtreeHelpers:
    def test_redacts_the_alert_methods_subtree(self) -> None:
        methods = _config()["alert_methods"]
        out = redact_alert_methods(methods)
        assert out["slack"]["webhook_url"] == REDACTED
        assert out["push"]["relay_token"] == REDACTED
        assert out["push"]["device_token"] == REDACTED
        assert out["slack"]["enabled"] is True
        assert out["log"] == {"enabled": True}

    def test_restores_the_alert_methods_subtree(self) -> None:
        stored = _config()["alert_methods"]
        incoming = {"slack": {"enabled": True, "webhook_url": REDACTED}}
        out = restore_alert_method_secrets(incoming, stored)
        assert out["slack"]["webhook_url"].endswith("/X/Y/Z")

    def test_subtree_paths_are_relative_to_alert_methods(self) -> None:
        assert ("*", "webhook_url") in ALERT_METHOD_SECRET_PATHS
        assert ("*", "relay_token") in ALERT_METHOD_SECRET_PATHS
        assert ("*", "device_token") in ALERT_METHOD_SECRET_PATHS
        assert ("alert_methods", "*", "webhook_url") in CONFIG_SECRET_PATHS


class TestSentinelSafety:
    def test_sentinel_never_survives_a_round_trip(self) -> None:
        """Redact then restore must return the original secrets exactly."""
        stored = _config()
        round_tripped = restore_config_secrets(redact_config(stored), stored)
        assert round_tripped == stored

    def test_sentinel_is_not_a_plausible_real_value(self) -> None:
        assert REDACTED.startswith("__")
        assert "://" not in REDACTED
