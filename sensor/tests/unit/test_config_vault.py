from __future__ import annotations

import stat
from copy import deepcopy

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

    from squirrelops_home_sensor.config_vault import VAULTED

    assert "token" not in clean["home_assistant"]
    assert "llm_api_key" not in clean["classifier"]
    # Method secrets leave a marker so hydration knows which field to fetch.
    assert clean["alert_methods"]["slack"]["webhook_url"] == VAULTED
    assert clean["alert_methods"]["push"]["relay_token"] == VAULTED
    assert clean["alert_methods"]["push"]["device_token"] == VAULTED
    assert "secret" not in str(clean["alert_methods"])
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


def test_webhook_signing_secret_is_vaulted_not_persisted() -> None:
    from squirrelops_home_sensor.config_vault import strip_vaulted_config_secrets

    clean = strip_vaulted_config_secrets(
        {"alert_methods": {"webhook": {"enabled": True, "webhook_url": "https://h", "signing_secret": "k"}}}
    )
    from squirrelops_home_sensor.config_vault import VAULTED

    assert clean["alert_methods"]["webhook"]["signing_secret"] == VAULTED
    assert clean["alert_methods"]["webhook"]["webhook_url"] == VAULTED
    assert clean["alert_methods"]["webhook"]["enabled"] is True


# ---------------------------------------------------------------------------
# #85: the vault governs every non-public alert-method field, not a list
# ---------------------------------------------------------------------------


def test_unknown_string_field_is_stripped_to_a_marker_not_persisted() -> None:
    from squirrelops_home_sensor.config_vault import VAULTED, strip_vaulted_config_secrets

    clean = strip_vaulted_config_secrets({
        "alert_methods": {
            "smtp": {
                "enabled": True,
                "min_severity": "high",
                "smtp_password": "future-secret",
                "retries": 3,
            }
        }
    })
    method = clean["alert_methods"]["smtp"]
    assert method["smtp_password"] == VAULTED, "a marker says where the vault holds the value"
    assert "future-secret" not in str(clean)
    assert method["enabled"] is True and method["min_severity"] == "high"
    assert method["retries"] == 3, "non-string unknown fields are settings, not credentials"


@pytest.mark.asyncio
async def test_unknown_string_field_round_trips_through_the_vault() -> None:
    from squirrelops_home_sensor.config_vault import (
        hydrate_vaulted_config_secrets,
        strip_vaulted_config_secrets,
    )

    store = MemoryStore()
    live = {"alert_methods": {"smtp": {"enabled": True, "smtp_password": "future-secret"}}}
    await hydrate_vaulted_config_secrets(live, store)  # migrates plaintext into the vault
    assert "future-secret" in store.values.values()

    persisted = strip_vaulted_config_secrets(live)
    reloaded = deepcopy(persisted)
    await hydrate_vaulted_config_secrets(reloaded, store)
    assert reloaded["alert_methods"]["smtp"]["smtp_password"] == "future-secret"


@pytest.mark.asyncio
async def test_legacy_yaml_with_the_field_removed_still_hydrates_known_secrets() -> None:
    # Older versions popped webhook_url from the YAML instead of leaving a
    # marker. Those installs must still get their secret back.
    from squirrelops_home_sensor.config_vault import hydrate_vaulted_config_secrets

    store = MemoryStore()
    seeded = {"alert_methods": {"slack": {"enabled": True, "webhook_url": "https://hook/secret"}}}
    await hydrate_vaulted_config_secrets(seeded, store)

    legacy = {"alert_methods": {"slack": {"enabled": True}}}
    await hydrate_vaulted_config_secrets(legacy, store)
    assert legacy["alert_methods"]["slack"]["webhook_url"] == "https://hook/secret"


@pytest.mark.asyncio
async def test_the_marker_itself_is_never_stored_as_a_secret() -> None:
    from squirrelops_home_sensor.config_vault import (
        VAULTED,
        hydrate_vaulted_config_secrets,
        sync_vaulted_config_secrets,
    )

    store = MemoryStore()
    with_marker = {"alert_methods": {"smtp": {"enabled": True, "smtp_password": VAULTED}}}
    await hydrate_vaulted_config_secrets(deepcopy(with_marker), store)
    await sync_vaulted_config_secrets({"alert_methods": {}}, with_marker, store)
    assert VAULTED not in store.values.values()
    assert not any(k.endswith(".smtp_password") for k in store.values)


def test_public_fields_are_the_api_boundarys_list() -> None:
    from squirrelops_home_sensor import config_fields
    from squirrelops_home_sensor.api import config_secrets

    assert config_secrets.ALERT_METHOD_PUBLIC_FIELDS is config_fields.ALERT_METHOD_PUBLIC_FIELDS, (
        "one allow-list governs redaction and the vault"
    )
