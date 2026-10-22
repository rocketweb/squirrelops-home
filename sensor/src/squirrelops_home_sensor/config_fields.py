"""Field classifications shared by the API boundary and the encrypted vault.

``alert_methods`` is keyed by arbitrary method names and accepts arbitrary
fields for forward compatibility. Only the fields named here are safe to
return to clients and to persist in plaintext. Every other string-valued
field is treated as a credential by both layers, so a new method's secret can
never be returned by a GET or written to the YAML file because nobody added
its name to a list.
"""

from __future__ import annotations

ALERT_METHOD_PUBLIC_FIELDS = frozenset({
    "enabled",
    "include_device_info",
    "min_severity",
    "relay_url",
})
