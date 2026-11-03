# SquirrelOps Home Agent Instructions

This repository ships a deception product. Read the Deception Integrity Rule below before making
any security-motivated change.

## Primary Source of Truth

1. `docs/DEVELOPMENT.md` for build, test, and local run workflows.
2. `docs/SECURITY_MODEL.md` for trust zones and threat model.
3. `docs/USER_GUIDE.md` for operator-facing behavior.
4. `docs/RELEASE_SECURITY.md` for signing and release posture.

## Deception Integrity Rule

Parts of this product are supposed to look weak. A scanner flagging a decoy is the product working,
not a defect. A security audit that "fixes" the apparent weaknesses of a decoy destroys the feature
and leaves a fingerprint behind.

**Control surface. Harden aggressively.**

- `sensor/src/squirrelops_home_sensor/api/` (routes, deps, config secrets)
- `sensor/src/squirrelops_home_sensor/alerts/`
- Update checking, install, packaging, and signing scripts
- The macOS app under `app/`

**Decoy surface. No change ships without a deception review.**

- `sensor/src/squirrelops_home_sensor/decoys/` including `credentials.py`, `orchestrator.py`, and `types/mimic.py`
- `sensor/src/squirrelops_home_sensor/scouts/` where decoy hosts and services are generated
- Decoy naming, banners, and any attacker-visible response content

**Never** add rate limiting, security headers, authentication, lockouts, or modern TLS to a decoy
service, and never remove verbose errors or version banners. Real vulnerable boxes do not have
those, and their presence is a tell.

**Always fine** on the decoy surface: typed exceptions plus internal debug logging, replacing
`assert` with an explicit raise, and swapping a non-cryptographic PRNG for a CSPRNG where the
output format is unchanged.

The test: does the change alter what an attacker *sees*, or only what an attacker can *predict*?
Changing predictability is good. Changing appearance needs review.

Canonical rule, full surface classification, review checklist, and testing notes live in the
umbrella repo at `squirrelops/docs/deception-integrity.md`.

## Public Disclosure Rule

This repository, its pull requests, issues, release notes, and tags are public. Never put real
machine names, hostnames, IP or MAC addresses, serial numbers, local usernames or home paths, Wi-Fi
names, or other details of a real test environment into any of them. Use neutral labels such as
"test host A" and documentation values (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, MAC
prefix `00:00:5e:00:53`). Where a test needs a private or CGNAT address, pick one that names no real
host. Product names such as "Studio Build Mac" and `studio-mini`, and the commit author identity,
are not covered.

## Known Gotchas

Each one matched the code on 2026-09-25.

Sensor (Python):

- aiosqlite returns tuples by default. Set `db.row_factory = aiosqlite.Row` for `row["column"]`
  access.
- Config defaults to `subnet: "auto"`, which must be resolved to a real CIDR before it is passed to
  the helper.
- The macOS ARP scanner returns unpadded MAC octets (`0:0:5e:0:53:a`), so `normalize_mac` pads
  each octet with `zfill(2)`.
- `DeviceManager` uses SQLite-assigned IDs (`cursor.lastrowid`), not a counter that resets on
  restart. `DeviceManager.load_known_devices()` must run at startup (`ScanLoop.run()` calls it), or
  every device is duplicated on each restart.
- The multi-signal fingerprint matcher needs non-MAC signals, so MAC-only ARP results depend on the
  direct MAC pre-match in `process_scan_result`.
- `bind_listener` in `privileged/xpc.py` does not work on macOS: fd passing over JSON fails across
  processes. Mimic decoys use port forwarding instead.
- `_get_mimicked_device_ids()` matches on `json_extract(d.config, '$.template_id')`. A
  `LIKE '%' || id || '%'` pattern false-matches (ID 3 matches 30, 31 and 33).
- `/decoys` returns every decoy type, mimics included. Do not add a `decoy_type != 'mimic'` filter
  there; the app needs authoritative mimic state from the API.
- Stale WebSocket events that reference deleted rows replay as phantom decoys or alerts.
  `EventLog.prune_orphaned_events()` runs at startup and on entity deletion to prevent it.
- Grouped security alerts deduplicate on the `issue_key` column (for example `port_risk:ssh:22`):
  one alert per issue with an `affected_devices` JSON array. The alert reactivates (clears
  `read_at`) when new devices appear.

App and helper (Swift):

- `SquirrelOpsHelper` is single-threaded RPC over a Unix socket, so a long operation blocks every
  call queued behind it.
- WebSocket event payloads must match the Swift Codable model shapes exactly (for example `id`, not
  `device_id`, with every required field present).
- `WSEventProcessor` batches ALL WebSocket event types (devices, alerts, decoys, system status) into
  one 200 ms flush. Applying an event during a delegate callback causes NSTableView
  reentrant-layout warnings.
- macOS mDNSResponder answers reverse DNS for aliased IPs with the machine's real hostname. mDNS
  service registration only partly masks this.
