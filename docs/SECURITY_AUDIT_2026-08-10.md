# Security audit validation, 2026-08-10

The Hermes report was reviewed against the current 2.0.1 source. Its headline
count of 107 findings is not supported by 107 distinct documented defects. The
report contains 12 medium entries, 15 low entries, repeated scanner matches,
false positives, positive findings, and long-term suggestions.

## Medium findings

| ID | Verdict | Resolution |
|---|---|---|
| M-01 | Intentional boundary, documentation gap | App Sandbox is incompatible with required system and helper operations. Hardened Runtime and library validation are enforced and the boundary is documented. |
| M-02 | Previously fixed | The literal exists only to migrate legacy stores. Migration is forced, generates a random key, and fails closed if legacy decryption fails. |
| M-03 | Intentional constrained probe | Self-signed LAN fingerprinting sends no credentials and already pins or constrains targets, disables redirects and proxies, and bounds responses. Documented in the security model. |
| M-04 | Mischaracterized | The cross-user socket is development-only in current production startup. Peer UID and audit-token application validation are the authorization boundary. |
| M-05 | Valid | Every production `assert` was replaced with an explicit runtime failure. |
| M-06 | Intentional | LAN reachability requires a non-loopback bind. Protected routes and WebSockets require mutual TLS. |
| M-07 | Valid | WebSocket close and dependency cleanup failures are now logged and separately handled. |
| M-08 | Valid defense in depth | Decoy credential selection now uses the operating system CSPRNG. |
| M-09 | Valid | Python networking tools now resolve only through fixed absolute path candidates. |
| M-10 | Valid | Home Assistant, LLM, and alert webhook credentials now persist in the encrypted secret store and are scrubbed from YAML. |
| M-11 | Valid dormant hardening | The currently unused plugin loader now rejects traversal, symlinks, untrusted owners, and writable plugin paths. |
| M-12 | Partly intentional, valid hardening gap | Paired clients are authorized to configure the sensor, but writes are now rate-limited per identity and emit value-free audit events. Unknown and immutable keys remain rejected by strict models. |

## Low findings

| IDs | Verdict |
|---|---|
| L-01, L-06, L-08 | False positives or safe parameterized behavior. No security fix required. |
| L-02 | Valid cleanup visibility issue. The named silent cleanup paths now log or catch expected transport failures. |
| L-03 | Valid certificate hygiene issue. New certificates omit `0.0.0.0`, and legacy server certificates rotate under the existing private CA. |
| L-04, L-07 | Duplicates of M-08 and M-05 and fixed with them. |
| L-05 | Intentional traversable, non-writable directory. The production socket remains disabled. |
| L-09 through L-15 | Positive findings, not vulnerabilities. |

SPKI pinning, CA rotation policy, additional binary integrity monitoring, and
plugin process isolation are future architecture options, not demonstrated
vulnerabilities in this report. The current app pins its private CA, package
releases verify signed code, and packaged operation does not load third-party
plugins.

## Dependency recheck

The report's claim that the dependency tree had no known vulnerabilities was
stale by final validation. A fresh advisory check identified `aiohttp` 3.14.2
and `cryptography` 49.0.0. Version 2.0.2 raises the minimums and lock to the
patched 3.14.3 and 50.0.0 releases. The exported production lock then passed a
second advisory scan with no known vulnerabilities.
