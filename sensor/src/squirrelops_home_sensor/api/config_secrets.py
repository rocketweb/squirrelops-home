"""Redaction of secret config values on the API boundary.

``GET /config`` used to return the sensor configuration verbatim, including the
Home Assistant long-lived token, the Slack webhook URL, and the classifier API
key. Clients cache API responses (the macOS app uses ``URLCache``, which
persists them unencrypted to disk), so any process running as the paired user
could read those credentials without ever holding the client certificate.

Redaction alone is not enough. The Settings screen keeps each secret in a
``@State`` string seeded from the GET response and writes the whole section back
whenever any field in it changes. A plain redaction would therefore round-trip
the marker straight back into ``config.yaml`` and destroy the real secret.

So the two halves here are a pair and must stay together:

``redact``
    Replaces configured secrets with :data:`REDACTED` on the way out.
``restore``
    Swaps :data:`REDACTED` back for the stored secret on the way in, so a client
    echoing the marker is a no-op rather than a destructive write.

A client that sends a genuinely new value still overwrites the secret, and one
that sends an empty string still clears it. Only the marker is special.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, MutableMapping, Sequence
from copy import deepcopy
from typing import Any

# Returned in place of a configured secret. Deliberately not URL-shaped and not
# token-shaped, so it cannot be mistaken for a usable credential and a
# collision with a real value is implausible.
REDACTED = "__squirrelops_redacted__"

# Matches every key at one level of a path, for sections keyed by arbitrary
# names (``alert_methods`` is keyed by method name).
WILDCARD = "*"

SecretPath = tuple[str, ...]

# Secrets in a full config document.
CONFIG_SECRET_PATHS: tuple[SecretPath, ...] = (
    ("sensor", "secret_passphrase"),
    ("classifier", "llm_api_key"),
    ("home_assistant", "token"),
    ("apns_relay_token",),
    ("alert_methods", WILDCARD, "webhook_url"),
    ("alert_methods", WILDCARD, "relay_token"),
    ("alert_methods", WILDCARD, "device_token"),
)

# The same secrets, relative to the ``alert_methods`` subtree that
# ``/config/alert-methods`` returns on its own.
ALERT_METHOD_SECRET_PATHS: tuple[SecretPath, ...] = (
    (WILDCARD, "webhook_url"),
    (WILDCARD, "relay_token"),
    (WILDCARD, "device_token"),
)

# ``alert_methods`` is intentionally extensible, so enumerating secret names
# fails open: a future ``smtp_password`` or ``bot_token`` would be returned by
# the API until somebody remembered to update the list above. Only fields that
# are safe and needed by clients are exposed. Every other configured value is
# treated as secret at the API boundary while explicit paths above continue to
# define the values managed by today's encrypted config vault.
ALERT_METHOD_PUBLIC_FIELDS = frozenset({
    "enabled",
    "include_device_info",
    "min_severity",
    "relay_url",
})


class _Missing:
    """Sentinel for "no stored value at this path"."""


_MISSING = _Missing()


def _walk(
    node: Any,
    path: Sequence[str],
    prefix: SecretPath = (),
) -> Iterator[tuple[MutableMapping[str, Any], str, SecretPath]]:
    """Yield ``(container, key, resolved_path)`` for each leaf ``path`` selects.

    ``resolved_path`` has wildcards replaced by the concrete keys they matched,
    so the caller can look the same leaf up in a second document. Anything that
    is not a mapping where the path expects one is skipped rather than raised
    on: config documents reaching this code have already been validated, but a
    partial ``PUT`` body has not.
    """
    if not path or not isinstance(node, Mapping):
        return
    head, rest = path[0], path[1:]
    if head == WILDCARD:
        keys = list(node.keys())
    else:
        keys = [head] if head in node else []
    for key in keys:
        resolved = (*prefix, key)
        if rest:
            yield from _walk(node[key], rest, resolved)
        elif isinstance(node, MutableMapping):
            yield node, key, resolved


def _lookup(root: Any, path: SecretPath) -> Any:
    """Return the value at ``path`` in ``root``, or :data:`_MISSING`."""
    node = root
    for key in path:
        if not isinstance(node, Mapping) or key not in node:
            return _MISSING
        node = node[key]
    return node


def _is_unset(value: Any) -> bool:
    """True for a secret that was never configured.

    Unset secrets are passed through untouched so the UI can distinguish "not
    configured" from "configured but hidden".
    """
    return value is None or value == ""


def redact(data: Any, paths: Sequence[SecretPath]) -> Any:
    """Return a copy of ``data`` with every configured secret replaced.

    The input is never mutated: callers pass the live config dict held by the
    app, and mutating it would drop the real secrets out of the running sensor.
    """
    out = deepcopy(data)
    if not isinstance(out, MutableMapping):
        return out
    for path in paths:
        for container, key, _resolved in _walk(out, path):
            if not _is_unset(container[key]):
                container[key] = REDACTED
    return out


def restore(
    incoming: Any,
    stored: Any,
    paths: Sequence[SecretPath],
) -> Any:
    """Return a copy of ``incoming`` with redaction markers resolved.

    Each marker is replaced by the matching secret from ``stored``. When
    ``stored`` holds nothing at that path the key is dropped entirely, because
    persisting the marker would turn it into the credential.
    """
    out = deepcopy(incoming)
    if not isinstance(out, MutableMapping):
        return out
    for path in paths:
        for container, key, resolved in _walk(out, path):
            if container[key] != REDACTED:
                continue
            kept = _lookup(stored, resolved)
            if isinstance(kept, _Missing) or kept == REDACTED:
                del container[key]
            else:
                container[key] = kept
    return out


def _redact_alert_method_unknowns(methods: Any) -> Any:
    """Hide every non-public alert-method field.

    This is deliberately fail closed. Alert methods accept arbitrary keys for
    forward compatibility, but an arbitrary key must never become an arbitrary
    credential disclosure through a GET endpoint.
    """
    out = deepcopy(methods)
    if not isinstance(out, MutableMapping):
        return out
    for method in out.values():
        if not isinstance(method, MutableMapping):
            continue
        for key in list(method):
            if key not in ALERT_METHOD_PUBLIC_FIELDS and not _is_unset(method[key]):
                method[key] = REDACTED
    return out


def _restore_alert_method_unknowns(incoming: Any, stored: Any) -> Any:
    """Resolve fail-closed markers for arbitrary alert-method fields."""
    out = deepcopy(incoming)
    if not isinstance(out, MutableMapping):
        return out
    for method_name, method in out.items():
        if not isinstance(method, MutableMapping):
            continue
        stored_method = (
            stored.get(method_name, {}) if isinstance(stored, Mapping) else {}
        )
        for key in list(method):
            if key in ALERT_METHOD_PUBLIC_FIELDS or method[key] != REDACTED:
                continue
            kept = (
                stored_method.get(key, _MISSING)
                if isinstance(stored_method, Mapping)
                else _MISSING
            )
            if isinstance(kept, _Missing) or kept == REDACTED:
                del method[key]
            else:
                method[key] = kept
    return out


def redact_config(config: Any) -> Any:
    """Redact secrets in a full config document."""
    out = redact(config, CONFIG_SECRET_PATHS)
    if isinstance(out, MutableMapping) and "alert_methods" in out:
        out["alert_methods"] = _redact_alert_method_unknowns(out["alert_methods"])
    return out


def restore_config_secrets(incoming: Any, stored: Any) -> Any:
    """Resolve redaction markers in a full or partial config update."""
    out = restore(incoming, stored, CONFIG_SECRET_PATHS)
    if isinstance(out, MutableMapping) and "alert_methods" in out:
        stored_methods = (
            stored.get("alert_methods", {}) if isinstance(stored, Mapping) else {}
        )
        out["alert_methods"] = _restore_alert_method_unknowns(
            out["alert_methods"], stored_methods
        )
    return out


def redact_alert_methods(methods: Any) -> Any:
    """Redact secrets in a bare ``alert_methods`` subtree."""
    return _redact_alert_method_unknowns(
        redact(methods, ALERT_METHOD_SECRET_PATHS)
    )


def restore_alert_method_secrets(incoming: Any, stored: Any) -> Any:
    """Resolve redaction markers in an ``alert_methods`` update."""
    return _restore_alert_method_unknowns(
        restore(incoming, stored, ALERT_METHOD_SECRET_PATHS),
        stored,
    )
