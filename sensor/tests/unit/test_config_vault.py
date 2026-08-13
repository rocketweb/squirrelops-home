from __future__ import annotations

import stat

import pytest
import yaml

from squirrelops_home_sensor.config_vault import (
    hydrate_vaulted_config_secrets,
    scrub_persisted_config_file,
    strip_vaulted_config_secrets,
    sync_vaulted_config_secrets,
)


class MemoryStore:
    def __init__(self, values: dict[str, str] | None = None) -> None:
        self.values = dict(values or {})

    async def get(self, key: str) -> str | None:
        return self.values.get(key)

    async def set(self, key: str, value: str) -> None:
        self.values[key] = value

    async def delete(self, key: str) -> None:
        self.values.pop(key, None)

    async def list_keys(self) -> list[str]:
        return list(self.values)


def _config() -> dict:
    return {
        "home_assistant": {"enabled": True, "token": "ha-secret"},
        "classifier": {"llm_api_key": "llm-secret"},
        "alert_methods": {
            "slack": {"enabled": True, "webhook_url": "https://hook/secret"},
            "push": {
                "enabled": True,
                "relay_token": "relay-secret",
                "device_token": "device-secret",
            },
        },
    }


@pytest.mark.asyncio
async def test_hydrate_migrates_plaintext_values_into_encrypted_store() -> None:
    config = _config()
    store = MemoryStore()

    await hydrate_vaulted_config_secrets(config, store)

    assert store.values["config.home_assistant.token"] == "ha-secret"
    assert store.values["config.classifier.llm_api_key"] == "llm-secret"
    assert "https://hook/secret" in store.values.values()
    assert "relay-secret" in store.values.values()
    assert "device-secret" in store.values.values()


@pytest.mark.asyncio
async def test_hydrate_restores_vaulted_value_into_runtime_config() -> None:
    config = _config()
    config["home_assistant"]["token"] = ""
    store = MemoryStore({"config.home_assistant.token": "stored-ha"})

    await hydrate_vaulted_config_secrets(config, store)

    assert config["home_assistant"]["token"] == "stored-ha"


@pytest.mark.asyncio
async def test_sync_updates_and_deletes_vaulted_values() -> None:
    previous = _config()
    store = MemoryStore()
    await hydrate_vaulted_config_secrets(previous, store)
    updated = _config()
    updated["home_assistant"]["token"] = "new-ha"
    updated["classifier"]["llm_api_key"] = ""

    await sync_vaulted_config_secrets(previous, updated, store)

    assert store.values["config.home_assistant.token"] == "new-ha"
    assert "config.classifier.llm_api_key" not in store.values


def test_strip_removes_all_config_credentials_without_mutating_input() -> None:
    config = _config()
    clean = strip_vaulted_config_secrets(config)

    assert "token" not in clean["home_assistant"]
    assert "llm_api_key" not in clean["classifier"]
    assert "webhook_url" not in clean["alert_methods"]["slack"]
    assert "relay_token" not in clean["alert_methods"]["push"]
    assert "device_token" not in clean["alert_methods"]["push"]
    assert config["home_assistant"]["token"] == "ha-secret"


def test_scrub_removes_legacy_plaintext_yaml_atomically(tmp_path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(_config()))
    path.chmod(0o644)

    assert scrub_persisted_config_file(tmp_path) is True

    saved = path.read_text()
    assert "ha-secret" not in saved
    assert "llm-secret" not in saved
    assert "https://hook/secret" not in saved
    assert "relay-secret" not in saved
    assert "device-secret" not in saved
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
