# SquirrelOps Home: Functional Test Plan

Branch: `bugfix/decoy-status-defects` (off `origin/main` @ acf1cf4)
Scope: full product, meaning sensor, app, and live install.
Policy: **findings are reported, not fixed.** Failures go to `qa/FINDINGS.md`.

## Method

| Kind | How it runs | Where |
|---|---|---|
| `AUTO-S` | pytest against the FastAPI app with fixtures | `sensor/tests/functional/` |
| `AUTO-A` | swift-testing against app types | `app/Tests/SquirrelOpsHomeTests/` |
| `LIVE` | script against the running install on this Mac | `qa/live/` |

`LIVE` cases depend on state that shifts between runs. Each records the state it
observed, so a later re-run can be compared honestly rather than assumed.

## Preconditions

- Sensor 2.0.1 running from `/Library/SquirrelOps/sensor`
- Repo checked out at `bugfix/decoy-status-defects`
- `sensor/.venv` present, and `swift build` succeeds
- `LIVE` cases needing root are marked, and emit the command rather than running it

## Known defects this plan should reproduce

Already diagnosed. The suite must demonstrate these rather than assume them.
They are expected failures on this branch.

| Ref | Defect | Covered by |
|---|---|---|
| KD-1 | `_service_to_primary` populated after `_active_mimics`, with an await between, so siblings render degraded during the window | B-08, B-09 |
| KD-2 | `buildPFRules` tcp pass branch unreachable from macOS, since `direct_ports` is always empty | C-04, C-05 |
| KD-3 | `AlertDispatcher` subscribes only to `alert.new`, so rolling decoy-trip alerts notify once | D-06, D-07 |
| KD-4 | `GET /config` returns secrets in plaintext with no `Cache-Control`, fixed on another branch but present here | G-01, G-02 |

---

## Group A: sensor API surface

Every endpoint reachable, correctly authenticated, and correct on the unhappy path.

| ID | Area | Verifies | Kind |
|---|---|---|---|
| A-01 | system | `GET /system/health` responds unauthenticated and omits version and sensor_id | AUTO-S |
| A-02 | system | `GET /system/status` requires a client cert, returns counts and api_protocol_version | AUTO-S |
| A-03 | system | `GET /system/status` decoy count excludes mimics when the orchestrator is present | AUTO-S |
| A-04 | system | `GET /system/profile` reports the active profile and its limits | AUTO-S |
| A-05 | system | `PUT /system/profile` applies a profile transactionally, invalid name rejected | AUTO-S |
| A-06 | system | `GET /system/learning` reports phase and elapsed hours | AUTO-S |
| A-07 | system | `GET /system/updates` with no manifest configured returns a graceful answer | AUTO-S |
| A-08 | devices | `GET /devices` paginates and excludes decoy IPs | AUTO-S |
| A-09 | devices | `GET /devices/{id}` 404s for an unknown id | AUTO-S |
| A-10 | devices | `PUT /devices/{id}` updates custom name and area only | AUTO-S |
| A-11 | devices | approve, reject, and ignore each write the expected trust status | AUTO-S |
| A-12 | devices | `POST /devices/{id}/verify` refreshes fingerprint confidence | AUTO-S |
| A-13 | devices | `GET /devices/{id}/fingerprints` and `/ports` return per-device detail | AUTO-S |
| A-14 | alerts | `GET /alerts` paginates, newest first, and filters by read state | AUTO-S |
| A-15 | alerts | `GET /alerts/{id}` returns parsed detail JSON, 404 when absent | AUTO-S |
| A-16 | alerts | `PUT /alerts/{id}/read` and `/action` are idempotent | AUTO-S |
| A-17 | alerts | `DELETE /alerts` clears history and records the clearing event | AUTO-S |
| A-18 | alerts | `GET /alerts/export` returns alerts plus incidents with a timestamp | AUTO-S |
| A-19 | alerts | `GET /incidents/{id}` and `PUT /incidents/{id}/read` | AUTO-S |
| A-20 | decoys | `GET /decoys` includes mimics and excludes retired rows | AUTO-S |
| A-21 | decoys | `GET /decoys/{id}` 404s for a retired decoy | AUTO-S |
| A-22 | decoys | restart, enable, and disable transition status correctly | AUTO-S |
| A-23 | decoys | `PUT /decoys/{id}/config` validates and persists | AUTO-S |
| A-24 | decoys | `PUT /decoys/{id}/hostname` renames every service on the host | AUTO-S |
| A-25 | decoys | `GET /decoys/{id}/credentials` and `/connections` paginate | AUTO-S |
| A-26 | config | `GET /config` and `PUT /config` merge semantics, protected fields rejected | AUTO-S |
| A-27 | config | `GET` and `PUT /config/alert-methods` round-trip | AUTO-S |
| A-28 | config | `GET /config/ha-status` blocks non-LAN URLs, the SSRF guard | AUTO-S |
| A-29 | ports | `GET /ports/network` aggregates open ports across devices | AUTO-S |
| A-30 | ports | `POST /ports/probe` validates target and port range | AUTO-S |
| A-31 | scouts | `GET /scouts/status` reports engine state, counts, and interval | AUTO-S |
| A-32 | scouts | `POST /scouts/run` is rejected while a run is in flight | AUTO-S |
| A-33 | scouts | `GET /scouts/profiles` and `/profiles/{id}` | AUTO-S |
| A-34 | scouts | `GET /scouts/mimics` reflects live mimic state | AUTO-S |
| A-35 | scouts | `POST /scouts/mimics/deploy` respects the capacity cap | AUTO-S |
| A-36 | scouts | `POST /scouts/mimics/{id}/restart` and `DELETE` | AUTO-S |
| A-37 | pairing | `GET /pairing/local/code` only for a local caller | AUTO-S |
| A-38 | pairing | challenge, verify, and complete happy path | AUTO-S |
| A-39 | pairing | `DELETE /pairing/{id}` revokes a paired client | AUTO-S |
| A-40 | ws | `/ws` rejects an unauthenticated socket | AUTO-S |
| A-41 | ws | `/ws` replays and then streams live events | AUTO-S |
| A-42 | auth | Every protected route returns 403 without a client cert | AUTO-S |
| A-43 | auth | Unknown routes 404 rather than leaking handler detail | AUTO-S |

## Group B: decoy and mimic lifecycle

| ID | Verifies | Kind |
|---|---|---|
| B-01 | Deploying a mimic inserts one decoy row per advertised port, first row `is_primary` | AUTO-S |
| B-02 | Every advertised port receives a distinct backend port in `port_remaps` | AUTO-S |
| B-03 | Deploy failure rolls back rows, alias, and PF state together | AUTO-S |
| B-04 | Removing a mimic soft-retires rows rather than deleting them | AUTO-S |
| B-05 | A retired mimic disappears from `/decoys` and `/scouts/mimics` | AUTO-S |
| B-06 | Removal releases the virtual IP for reuse | AUTO-S |
| B-07 | Resume at startup rebuilds runtime state from persisted rows | AUTO-S |
| B-08 | **KD-1** All services of an operational host report `active`, never mixed | AUTO-S |
| B-09 | **KD-1** A status read concurrent with registration never reports a false `degraded` | AUTO-S |
| B-10 | mDNS registration failure degrades the whole host, not one service | AUTO-S |
| B-11 | `effective_mimic_status` leaves a persisted `stopped` row alone | AUTO-S |
| B-12 | The capacity cap is enforced across concurrent deploys | AUTO-S |
| B-13 | Hostname collision resolution produces a unique `.local` label | AUTO-S |
| B-14 | Restart preserves decoy id, connection counts, and host grouping | AUTO-S |
| B-15 | A stale removal request for a rotated host generation is refused | AUTO-S |

## Group C: network isolation and PF

| ID | Verifies | Kind |
|---|---|---|
| C-01 | Every advertised port emits exactly one `rdr pass` rule | AUTO-S |
| C-02 | Each protected IP emits an ICMP pass and a `block drop in quick` | AUTO-S |
| C-03 | Rules are destination-scoped to the virtual IP, never to a wildcard | AUTO-S |
| C-04 | **KD-2** `direct_ports` is empty from both macOS call sites | AUTO-S |
| C-05 | **KD-2** The tcp pass branch is unreachable from the macOS path | AUTO-S |
| C-06 | An invalid IP or port in a forwarding rule is rejected, not emitted | AUTO-S |
| C-07 | Duplicate endpoint entries merge instead of shadowing later ports | AUTO-S |
| C-08 | Startup quarantine denies every persisted alias in one atomic load | AUTO-S |
| C-09 | Failed cleanup retains PF isolation rather than opening the alias | AUTO-S |
| C-10 | The live anchor contains a block rule for every live alias | LIVE |
| C-11 | No live PF rule matches a destination outside the virtual IP range | LIVE |
| C-12 | Every lo0 alias is a `/32` | LIVE |

## Group D: alert pipeline

| ID | Verifies | Kind |
|---|---|---|
| D-01 | A decoy trip writes one `decoy_connections` row and increments the counter | AUTO-S |
| D-02 | A first trip from a source creates one alert and publishes `alert.new` | AUTO-S |
| D-03 | Repeat trips fold into the same unread alert rather than creating rows | AUTO-S |
| D-04 | Two or more endpoints promote the title to a port scan and set `detection_method` | AUTO-S |
| D-05 | IPP discovery on 631 is recorded without raising an alert | AUTO-S |
| D-06 | **KD-3** A folded trip publishes `alert.updated` | AUTO-S |
| D-07 | **KD-3** The dispatcher delivers nothing for `alert.updated` | AUTO-S |
| D-08 | Clearing an alert re-arms notification for the next trip | AUTO-S |
| D-09 | A credential trip raises critical and suppresses the duplicate trip alert | AUTO-S |
| D-10 | Incident grouping attaches alerts by source IP within the window | AUTO-S |
| D-11 | Grouped port-risk alerts dedupe on `issue_key` and reactivate on new devices | AUTO-S |
| D-12 | Retention deletes aged alerts and prunes their orphaned events | AUTO-S |
| D-13 | Slack delivery formats Block Kit and honors `min_severity` | AUTO-S |
| D-14 | A delivery failure does not discard the forensic connection record | AUTO-S |

## Group E: app behavior

| ID | Verifies | Kind |
|---|---|---|
| E-01 | `AppState.menuBarStatus` for each connection and alert combination | AUTO-A |
| E-02 | Silencing suppresses critical presentation but not the underlying alerts | AUTO-A |
| E-03 | Decoy IPs are filtered out of the visible device list | AUTO-A |
| E-04 | `activeDecoyDeploymentCount` counts hosts, not per-port rows | AUTO-A |
| E-05 | A grouped alert resurfaces when its revision changes | AUTO-A |
| E-06 | `WSEventProcessor` batches all event types into one flush | AUTO-A |
| E-07 | Event replay does not create phantom entities | AUTO-A |
| E-08 | `ConnectionState` transitions on auth failure and incompatibility | AUTO-A |
| E-09 | `ActionQueue` retries and preserves ordering | AUTO-A |
| E-10 | Pairing crypto round-trips and rejects a tampered challenge | AUTO-A |
| E-11 | Keychain store persists and deletes paired credentials | AUTO-A |
| E-12 | `Endpoint` builds correct paths and methods for all cases | AUTO-A |
| E-13 | Models decode real sensor payload shapes without loss | AUTO-A |
| E-14 | `SensorAPICompatibility` rejects an unsupported protocol version | AUTO-A |
| E-15 | Timestamp presentation is stable across locales | AUTO-A |
| E-16 | Alert detail renders the decoy section from stored detail fields | AUTO-A |

## Group F: live system

| ID | Verifies | Kind |
|---|---|---|
| F-01 | The sensor process is running and owned by `_squirrelops` | LIVE |
| F-02 | Both LaunchDaemons are loaded | LIVE |
| F-03 | The sensor API answers on 8443 and demands a client certificate | LIVE |
| F-04 | Sensor version matches `release-components.json` | LIVE |
| F-05 | Every live lo0 alias has a matching non-retired decoy row | LIVE |
| F-06 | Every non-retired mimic row has a live alias | LIVE |
| F-07 | `_squirrelops._tcp` is advertised exactly once | LIVE |
| F-08 | Each mimic hostname resolves to its own virtual IP only | LIVE |
| F-09 | No virtual IP collides with a real DHCP lease on the subnet | LIVE |
| F-10 | DB integrity check passes and schema version matches the code | LIVE |
| F-11 | No orphaned events reference deleted alerts or decoys | LIVE |
| F-12 | The helper socket exists with the expected owner and mode | LIVE |
| F-13 | Log files are not world-readable | LIVE |

## Group G: security and regression

| ID | Verifies | Kind |
|---|---|---|
| G-01 | **KD-4** `GET /config` does not return secret values | AUTO-S |
| G-02 | **KD-4** Config responses are marked `no-store` | AUTO-S |
| G-03 | `config.yaml` and the secret store are not world-readable | LIVE |
| G-04 | `PUT /config` cannot relocate `data_dir` or set `secret_passphrase` | AUTO-S |
| G-05 | `credential_filename` path traversal is sanitized | AUTO-S |
| G-06 | HA status blocks cloud-metadata and public URLs | AUTO-S |
| G-07 | The LLM classifier redacts MAC and IP before sending a prompt | AUTO-S |
| G-08 | Decoy banner sanitization strips control bytes | AUTO-S |
| G-09 | Pairing rejects an unsigned or mismatched client binary | AUTO-S |
| G-10 | A revoked pairing cannot reuse its client certificate | AUTO-S |

---

# Coverage review

Second pass, checked case by case against the inventory rather than by eye.
All 53 endpoints were already covered. The gaps were in **subsystems**, not
routes: the first draft followed the API surface and under-weighted code that
no endpoint reaches directly.

| Gap found | Why it matters | Added |
|---|---|---|
| Whole `scanner/` package untouched | The two-phase scan pipeline is the sensor's primary job, and several known past defects live here | Group H |
| `db/migrations.py` untested | A bad migration corrupts every install on upgrade, and the V8 migration prunes events | I-01 to I-03 |
| `events/` bus and log semantics | Ordering and replay drive the whole app UI, and replay bugs previously created phantom entities | I-05 to I-07 |
| `fingerprint/` matcher | Device identity is what alerting attributes to, and the MAC-only path has bitten before | J-02, J-03 |
| `security/analyzer.py` | Grouped port-risk alerts were only covered incidentally by D-11 | J-07, J-08 |
| `secrets/` store | Never exercised, and it holds the credentials the whole product depends on | G-11, G-12 |
| `network/virtual_ip.py` allocator | Only touched indirectly by B-06, and exhaustion and reuse are the risky paths | C-13 to C-15 |
| `privileged/` RPC boundary | The trust boundary to a root helper, previously only covered through PF output | C-16 |
| App `Connection/`, `Desktop/`, `Pairing/` modules | Six modules with no case at all | E-17 to E-22 |

Deliberately still uncovered, with reasons:

- **SwiftUI view bodies.** Rendering is not meaningfully unit-testable here. The
  state each view derives from is covered in Group E instead.
- **`linux_sidecar.py`.** Out of scope for a macOS install. Flagged because
  `direct_ports` may be live on that path, which matters for KD-2.
- **Real network scanning against the live subnet.** Group H uses fixtures. A
  live scan would be non-deterministic and would touch the neighbors' devices.

## Group H: scanning and discovery

| ID | Verifies | Kind |
|---|---|---|
| H-01 | Phase 1 creates devices before any port data arrives | AUTO-S |
| H-02 | A port-scan failure never blocks device creation | AUTO-S |
| H-03 | `normalize_mac` zero-pads unpadded macOS ARP octets | AUTO-S |
| H-04 | ARP identity conflicts are detected and reported | AUTO-S |
| H-05 | The scanner excludes its own interface MACs from conflict reporting | AUTO-S |
| H-06 | Port scanning is bounded by the concurrency semaphore | AUTO-S |
| H-07 | A per-port timeout is enforced | AUTO-S |
| H-08 | HTTP probe ports attempt a banner and others do not | AUTO-S |
| H-09 | The mDNS browser records service instances and hostnames | AUTO-S |
| H-10 | The SSDP scanner parses device descriptions | AUTO-S |
| H-11 | `ScanLoop.run()` loads known devices before the first scan | AUTO-S |
| H-12 | Rescan reconciles without duplicating devices after restart | AUTO-S |
| H-13 | Decoy virtual IPs are excluded from scan results | AUTO-S |

## Group I: data layer and events

| ID | Verifies | Kind |
|---|---|---|
| I-01 | A fresh DB creates every table at the current schema version | AUTO-S |
| I-02 | Each migration applies in order and is idempotent | AUTO-S |
| I-03 | The V8 migration prunes orphaned events | AUTO-S |
| I-04 | `row_factory` is set so queries return mappings, not tuples | AUTO-S |
| I-05 | `EventLog.prune_orphaned_events` deletes only true orphans | AUTO-S |
| I-06 | The event bus delivers to subscribers in sequence order | AUTO-S |
| I-07 | Replay from a sequence returns the correct window | AUTO-S |
| I-08 | Foreign keys are enforced on the live connection | AUTO-S |

## Group J: device intelligence

| ID | Verifies | Kind |
|---|---|---|
| J-01 | OUI lookup resolves a known prefix and declines a locally administered MAC | AUTO-S |
| J-02 | Multi-signal fingerprint matching requires a non-MAC signal | AUTO-S |
| J-03 | A MAC-only ARP scan still matches via the direct pre-match path | AUTO-S |
| J-04 | Composite confidence follows the configured signal weights | AUTO-S |
| J-05 | The auto-approve threshold promotes trust status | AUTO-S |
| J-06 | Connection baselines record and then detect deviation | AUTO-S |
| J-07 | `SecurityInsightAnalyzer` groups findings by `issue_key` | AUTO-S |
| J-08 | Risk description and remediation are populated per risk type | AUTO-S |

## Added to existing groups

| ID | Verifies | Kind |
|---|---|---|
| C-13 | The virtual IP allocator stays inside the configured range | AUTO-S |
| C-14 | The allocator refuses to exceed `max_virtual_ips` | AUTO-S |
| C-15 | The allocator does not reuse an IP still held by a live alias | AUTO-S |
| C-16 | Helper RPC rejects a malformed rule payload at the boundary | AUTO-S |
| E-17 | `MacNotificationService` honors enabled state and minimum severity | AUTO-A |
| E-18 | `MenuBarLayoutMetrics` sizes correctly for each alert-count combination | AUTO-A |
| E-19 | `PairingManager` stores, loads, and deletes a paired sensor | AUTO-A |
| E-20 | `SensorConnectionService` reconnects with backoff | AUTO-A |
| E-21 | `HelperManager` detects an installed helper without reinstalling | AUTO-A |
| E-22 | `SensorInstaller` refuses an unsigned payload | AUTO-A |
| G-11 | The encrypted secret store round-trips and rejects a wrong passphrase | AUTO-S |
| G-12 | Re-encryption preserves every stored secret | AUTO-S |

---

**Totals after review:** A 43, B 15, C 16, D 14, E 22, F 13, G 12, H 13, I 8,
J 8, giving **164 cases**. The review added 41.
