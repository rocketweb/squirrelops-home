"""Encrypted persistence for credentials embedded in runtime configuration."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, MutableMapping
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from squirrelops_home_sensor.secrets.store import SecretStore
from squirrelops_home_sensor.secure_io import atomic_write_private_text

_FIXED_SECRETS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("home_assistant", "token"), "config.home_assistant.token"),
    (("classifier", "llm_api_key"), "config.classifier.llm_api_key"),
    (("apns_relay_token",), "config.apns_relay_token"),
)

_ALERT_METHOD_SECRET_FIELDS = (
    "webhook_url",
    "relay_token",
    "device_token",
)


def _alert_method_key(method_name: str, field_name: str) -> str:
    digest = hashlib.sha256(method_name.encode("utf-8")).hexdigest()
    return f"config.alert_methods.{digest}.{field_name}"


def _get_path(config: Mapping[str, Any], path: tuple[str, ...]) -> Any:
    node: Any = config
    for key in path:
        if not isinstance(node, Mapping) or key not in node:
            return None
        node = node[key]
    return node


def _set_path(config: MutableMapping[str, Any], path: tuple[str, ...], value: str) -> None:
    node: MutableMapping[str, Any] = config
    for key in path[:-1]:
        child = node.setdefault(key, {})
        if not isinstance(child, MutableMapping):
            raise RuntimeError(f"Configuration secret path is not an object: {path!r}")
        node = child
    node[path[-1]] = value


def _secret_locations(config: Mapping[str, Any]) -> dict[str, tuple[tuple[str, ...], str]]:
    locations = {
        store_key: (path, str(_get_path(config, path) or ""))
        for path, store_key in _FIXED_SECRETS
    }
    methods = config.get("alert_methods", {})
    if isinstance(methods, Mapping):
        for method_name, method_config in methods.items():
            if not isinstance(method_name, str) or not isinstance(method_config, Mapping):
                continue
            for field_name in _ALERT_METHOD_SECRET_FIELDS:
                path = ("alert_methods", method_name, field_name)
                locations[_alert_method_key(method_name, field_name)] = (
                    path,
                    str(method_config.get(field_name) or ""),
                )
    return locations


async def hydrate_vaulted_config_secrets(
    config: MutableMapping[str, Any],
    store: SecretStore,
) -> None:
    """Migrate plaintext values into the vault or hydrate absent runtime values."""
    for store_key, (path, configured) in _secret_locations(config).items():
        if configured:
            await store.set(store_key, configured)
            continue
        stored = await store.get(store_key)
        if stored:
            _set_path(config, path, stored)


async def sync_vaulted_config_secrets(
    previous: Mapping[str, Any],
    updated: Mapping[str, Any],
    store: SecretStore,
) -> dict[str, str | None]:
    """Apply changed runtime credentials and return a rollback snapshot."""
    before = _secret_locations(previous)
    after = _secret_locations(updated)
    snapshot: dict[str, str | None] = {}
    applied: list[str] = []
    try:
        for store_key in sorted(set(before) | set(after)):
            old_value = before.get(store_key, ((), ""))[1]
            new_value = after.get(store_key, ((), ""))[1]
            stored_value = await store.get(store_key)
            if old_value == new_value and stored_value == (new_value or None):
                continue
            snapshot[store_key] = stored_value
            if new_value:
                await store.set(store_key, new_value)
            else:
                await store.delete(store_key)
            applied.append(store_key)
    except Exception:
        await restore_vaulted_config_secrets(snapshot, store, keys=applied)
        raise
    return snapshot


async def restore_vaulted_config_secrets(
    snapshot: Mapping[str, str | None],
    store: SecretStore,
    *,
    keys: list[str] | None = None,
) -> None:
    """Restore a snapshot after a failed config transaction."""
    for store_key in reversed(keys if keys is not None else list(snapshot)):
        old_value = snapshot.get(store_key)
        if old_value is None:
            await store.delete(store_key)
        else:
            await store.set(store_key, old_value)


def strip_vaulted_config_secrets(config: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy with vault-managed credentials removed."""
    clean = deepcopy(dict(config))
    for path, _store_key in _FIXED_SECRETS:
        parent = _get_path(clean, path[:-1])
        if isinstance(parent, MutableMapping):
            parent.pop(path[-1], None)
    methods = clean.get("alert_methods", {})
    if isinstance(methods, MutableMapping):
        for method_config in methods.values():
            if isinstance(method_config, MutableMapping):
                for field_name in _ALERT_METHOD_SECRET_FIELDS:
                    method_config.pop(field_name, None)
    return clean


def scrub_persisted_config_file(data_dir: Path) -> bool:
    """Remove legacy plaintext credentials from the runtime YAML file."""
    path = data_dir / "config.yaml"
    if not path.is_file():
        return False
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        return False
    clean = strip_vaulted_config_secrets(loaded)
    if clean == loaded:
        return False
    atomic_write_private_text(
        path,
        yaml.safe_dump(clean, default_flow_style=False, sort_keys=False),
    )
    return True
