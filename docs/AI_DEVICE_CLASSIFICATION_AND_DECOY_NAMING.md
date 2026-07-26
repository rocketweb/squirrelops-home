# Optional AI Device Classification and Decoy Naming

## Purpose

SquirrelOps works without an AI provider. When a provider is configured, the
sensor may use it for two narrow tasks:

1. Classify a newly discovered device when deterministic local signatures do
   not identify it.
2. Suggest plausible names for some newly created fake hosts after reviewing a
   bounded sample of existing hostnames.

The AI does not analyze alerts, inspect packet payloads, choose deployment
targets, rename existing decoys, or perform privileged network operations.

## Naming Model

Fake-host naming is a hybrid:

- The deterministic fallback uses ordinary home and small-business names such
  as `files`, `media`, `office`, `backup`, `printer`, and `automation`.
- Generated names do not receive an IP-derived number or hexadecimal suffix.
- If several observed real hostnames use a consistent terminal identifier,
  identifiers are permitted when needed for uniqueness.
- When AI is enabled, at most half of a new deployment batch receives an AI
  suggestion. The rest use the deterministic vocabulary so the network does not
  acquire an implausibly uniform synthetic pattern.
- Existing fake-host identities remain durable across restarts and upgrades.

## AI Input and Output

The naming request contains:

- A bounded, sanitized sample of observed real-device hostname labels.
- Whether the local deterministic detector found an identifier convention.
- The number of suggestions requested.

The response is a JSON list of hostname labels. Every returned value is treated
as untrusted. The sensor locally normalizes it, enforces DNS-label length and
character rules, rejects real-device and sensor-host collisions, rejects
duplicates and IP-address-like values, and falls back to deterministic naming
when the request or validation fails.

Cloud providers receive the hostname sample. LM Studio, Ollama, and private
custom endpoints keep that request wherever the configured endpoint runs.
Choosing no provider disables both AI classification and AI naming.

## Device Classification

Local OUI, mDNS, and DHCP signatures run first. For a newly unresolved or
incomplete device, AI waits until port scanning and discovery enrichment finish.
The request may include:

- The three-octet MAC OUI prefix, never the full MAC address.
- Sanitized DNS and mDNS names.
- Open TCP port numbers and detected service names, never banners.
- DHCP option codes in observed order.
- mDNS service types.
- Available UPnP friendly name, manufacturer, model, and server metadata.

Fingerprint hashes and connection destinations remain local and are never
included. IP addresses and full MAC addresses embedded inside untrusted metadata
are redacted before the prompt is constructed. The response may supply
manufacturer, device type, model, and confidence. Existing deterministic or
UPnP values take precedence; AI fills missing classification fields. Accepted
fields are persisted so the classification survives a sensor restart.

## Failure Behavior

AI is never required for deployment. Timeouts, malformed responses, rejected
names, or an unavailable provider are logged and produce the deterministic
fallback. They do not stop scanning, alerting, or decoy deployment.
