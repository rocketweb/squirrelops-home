"""Encrypted persistence for credentials embedded in runtime configuration."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, MutableMapping
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from squirrelops_home_sensor.config_fields import ALERT_METHOD_PUBLIC_FIELDS
from squirrelops_home_sensor.secrets.store import SecretStore
from squirrelops_home_sensor.secure_io import atomic_write_private_text

_FIXED_SECRETS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("home_assistant", "token"), "config.home_assistant.token"),
    (("classifier", "llm_api_key"), "config.classifier.llm_api_key"),
    (("apns_relay_token",), "config.apns_relay_token"),
)

# Alert-method fields older releases stripped from the YAML outright. Their
# names are probed at hydration so an install written by one of those releases
# still gets its values back; everything newer leaves a marker instead.
_LEGACY_ALERT_METHOD_SECRET_FIELDS = (
    "webhook_url",
    "relay_token",
    "device_token",
    "signing_secret",
)

# Written to the YAML file in place of a vaulted value. Not URL-shaped and not
# token-shaped, so it cannot be mistaken for a usable value, and it tells
# hydration which field to fetch without the vault keeping an index.
VAULTED = "__squirrelops_vaulted__"


def _alert_method_key(method_name: str, field_name: str) -> str:
    digest = hashlib.sha256(method_name.encode("utf-8")).hexdigest()
    return f"config.alert_methods.{digest}.{field_name}"


def _is_vaulted_field(field_name: str, value: Any) -> bool:
    """Every non-public string field of an alert method is a credential."""
    return field_name not in ALERT_METHOD_PUBLIC_FIELDS and isinstance(value, str)


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


def _configured_value(value: Any) -> str:
    """The plaintext a config holds for a secret path; markers count as unset."""
    if not isinstance(value, str) or value == VAULTED:
        return ""
    return value


def _secret_locations(config: Mapping[str, Any]) -> dict[str, tuple[tuple[str, ...], str]]:
    locations = {
        store_key: (path, _configured_value(_get_path(config, path)))
        for path, store_key in _FIXED_SECRETS
    }
    methods = config.get("alert_methods", {})
    if isinstance(methods, Mapping):
        for method_name, method_config in methods.items():
            if not isinstance(method_name, str) or not isinstance(method_config, Mapping):
                continue
            field_names = set(_LEGACY_ALERT_METHOD_SECRET_FIELDS)
            field_names.update(
                name
                for name, value in method_config.items()
                if isinstance(name, str) and _is_vaulted_field(name, value)
            )
            for field_name in sorted(field_names):
                path = ("alert_methods", method_name, field_name)
                locations[_alert_method_key(method_name, field_name)] = (
                    path,
                    _configured_value(method_config.get(field_name)),
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
        elif _get_path(config, path) == VAULTED:
            # A marker with nothing behind it: drop it rather than hand the
            # sentinel to a handler as if it were a credential.
            parent = _get_path(config, path[:-1])
            if isinstance(parent, MutableMapping):
                parent.pop(path[-1], None)


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
    """Return a copy safe to persist: fixed secrets removed, method secrets marked."""
    clean = deepcopy(dict(config))
    for path, _store_key in _FIXED_SECRETS:
        parent = _get_path(clean, path[:-1])
        if isinstance(parent, MutableMapping):
            parent.pop(path[-1], None)
    methods = clean.get("alert_methods", {})
    if isinstance(methods, MutableMapping):
        for method_config in methods.values():
            if not isinstance(method_config, MutableMapping):
                continue
            for field_name, value in list(method_config.items()):
                if isinstance(field_name, str) and _is_vaulted_field(field_name, value):
                    method_config[field_name] = VAULTED
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
