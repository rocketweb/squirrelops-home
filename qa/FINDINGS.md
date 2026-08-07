# SquirrelOps Home: Defect Findings

Branch: `bugfix/decoy-status-defects` (off `origin/main` @ acf1cf4)
Run date: 2026-08-07
Policy: **reported, not fixed.** No product code was changed.

## Execution status

| Group | Cases planned | Implemented | Run | Result |
|---|---|---|---|---|
| Known defects (B-08, B-09, C-04, D-06, D-07, G-01, G-02) | 7 | 14 assertions | yes | 9 fail, 5 pass |
| D, alert pipeline (D-01 to D-05, D-08 to D-14) | 12 | 14 assertions | yes | all pass |
| B, mimic lifecycle (B-01 to B-07, B-10 to B-15) | 13 | 13 assertions | yes | all pass |
| C, isolation and PF, Python side (C-06, C-08, C-09, C-13 to C-16) | 7 | 27 assertions | yes | 4 fail, 23 pass |
| C, PF rule builder (C-01 to C-03, C-05, C-07) | 5 | already covered | yes | 63 existing tests pass |
| H, scanning (H-03, H-05) | 2 | 6 assertions | yes | all pass |
| H, remainder (H-01, H-02, H-04, H-06 to H-13) | 11 | already covered | yes | 134 existing tests |
| A, E, F, G, I, J remainder | 107 | not yet | no | pending |

**Running total: 74 assertions, 13 failed, 61 passed.** The full sensor suite is
1934 passed with the same 9 failures, so the functional cases introduced no
regressions.

Groups D and B produced **no new defects**. The alert pipeline behaves correctly
apart from DEF-002, and the mimic lifecycle behaves correctly apart from
DEF-003.

`sensor/tests/functional/test_known_defects.py`, run with
`.venv/bin/python -m pytest tests/functional/ -p no:randomly`.

Every failure below is a reproduction, not a broken test. The passing cases are
controls that show the assertions are sound.

---

## DEF-001 (Critical): config endpoint returns every stored credential

**Case:** G-01. **Confirms:** KD-4. **5 failing assertions.**

`GET /config` returns the sensor configuration verbatim. Four separate secrets
come back in plaintext to any paired client:

| Secret | Config path |
|---|---|
| Home Assistant long-lived token | `home_assistant.token` |
| Slack incoming webhook URL | `alert_methods.slack.webhook_url` |
| Classifier API key | `classifier.llm_api_key` |
| Secret store passphrase | `sensor.secret_passphrase` |

`GET /config/alert-methods` returns the webhook as well.

**Repro**

```
.venv/bin/python -m pytest tests/functional/test_known_defects.py::TestG01ConfigDoesNotReturnSecrets -p no:randomly
```

**Impact.** The macOS app caches API responses through `URLCache`, which writes
them unencrypted to `~/Library/Caches/com.squirrelops.home/Cache.db`. That file
is mode 644 and owned by the user, so any process running as that user reads
every credential without ever holding the client certificate. Confirmed by
extraction on this machine earlier in the session.

**Code:** [routes_config.py:270](../sensor/src/squirrelops_home_sensor/api/routes_config.py)
returns `config` directly.

**Note.** A fix exists on `security/redact-config-secrets`, PR #23, unmerged. It
is not on this branch, so these failures are expected here and are the correct
result for main.

---

## DEF-002 (High): rolling decoy-trip alerts notify once, then go silent

**Case:** D-07. **Confirms:** KD-3. **1 failing assertion.**

`AlertDispatcher.subscribe_to` subscribes to `["alert.new"]` only.
`DecoyAlertHandler._create_or_update_trip_alert` folds every repeat trip from a
source into the existing unread alert and publishes `alert.updated`, which no
subscriber consumes.

D-06 passes and proves the event is published, so the gap is on the consuming
side, not the producing side.

**Repro**

```
.venv/bin/python -m pytest tests/functional/test_known_defects.py::TestD07UpdatedAlertsAreDelivered -p no:randomly
```

**Impact.** An intrusion produces exactly one notification, on the first
connection. Observed live: alert 312 accumulated 1195 connections over 10 days
across 24 decoys and 31 endpoints and sent one Slack message, on the first hit.

It also self-perpetuates. The fold-in query matches
`WHERE read_at IS NULL AND actioned_at IS NULL`, so an uncleared alert keeps
absorbing hits and can never fire again. Clearing it re-arms notification.

**Code:** [dispatcher.py:91](../sensor/src/squirrelops_home_sensor/alerts/dispatcher.py),
[decoy_handler.py:305](../sensor/src/squirrelops_home_sensor/alerts/decoy_handler.py)

**Not a one-line fix.** Adding `alert.updated` to the subscribe list would
notify on every connection in a scan burst. The fix has to decide what an update
notification means, most likely re-notify on severity increase or on a new
endpoint, with rate limiting.

---

## DEF-003 (Medium): status read during registration invents a failure

**Case:** B-09. **Confirms:** KD-1. **1 failing assertion.**

```
assert 'degraded' == 'active'
```

All three call sites publish into `_active_mimics` **before** populating
`_service_to_primary`, with an `await` between them:

```python
self._active_mimics[decoy_id] = mimic
service_rows = await self._refresh_service_mapping(decoy_id)
```

`_refresh_service_mapping` runs a DB query, so the event loop can serve an API
request inside that window. `is_mimic_operational` then does:

```python
primary_id = self._service_to_primary.get(decoy_id, decoy_id)  # silent fallback
mimic = self._active_mimics.get(primary_id)                     # keyed by primary
if mimic is None:
    return False                                                # renders "degraded"
```

The primary service resolves because its id is the key. Every sibling falls
through to the default, misses `_active_mimics`, and reports degraded while the
persisted status stays `active`.

B-08 passes with the mapping populated, which isolates the cause to the window
rather than to the status logic.

**Repro**

```
.venv/bin/python -m pytest tests/functional/test_known_defects.py::TestB09NoFalseDegradedDuringRegistration -p no:randomly
```

**Impact.** Transient false DEGRADED in the Scouts screen. Cosmetic, but it
erodes trust in the one screen meant to report deception health, and the silent
`.get(decoy_id, decoy_id)` default means a genuinely missing mapping is
indistinguishable from a real failure.

**Code:** [orchestrator.py:231](../sensor/src/squirrelops_home_sensor/scouts/orchestrator.py),
sites at 1393, 3114, 3826.

**Suggested direction.** Populate the mapping before publishing into
`_active_mimics` so no await separates them. Three sites, no behavior change
otherwise. Separately, consider making the missing-mapping case explicit rather
than defaulting.

**Caveat.** This reproduces the mechanism. It does not prove it caused the
mixed-status screenshot from 2026-08-03, whose decoy rows no longer exist. That
screenshot showed 3 active and 2 degraded on one host, whereas this race
predicts 1 active with the rest degraded. Either a second cause exists or the
screenshot caught a different transition.

---

## DEF-004 (Low): unreachable branch weakens a default-deny

**Case:** C-04. **Confirms:** KD-2. **3 passing tests characterize it.**

Not a behavior defect. The PF rules are correct and the tests confirm it:
`direct_ports` is empty from both macOS call sites, every advertised port is
redirected through `rdr pass`, and high ports get no special treatment.

The finding is that `buildPFRules` carries a
`pass in quick ... proto tcp ... port { … }` branch that no macOS caller can
reach, because `direct_ports` is hardcoded empty at
[port_forward.py:158](../sensor/src/squirrelops_home_sensor/network/port_forward.py)
with a comment explaining that directly allowing a virtual-IP port would let a
wildcard-bound host daemon answer on the decoy address.

**Impact.** Dead code that, if ever fed a non-empty list, would punch exactly
the hole the comment forbids. Low severity today, latent risk.

**Code:** [RPCMethods.swift:1486](../app/Sources/SquirrelOpsHelper/RPCMethods.swift)

**Before removing:** check `privileged/linux_sidecar.py`, which also accepts
`direct_ports` and may legitimately use it.

---

## Passing control cases

| Case | Confirms |
|---|---|
| B-08 | Host status is uniform when the mapping is populated |
| C-04 (x3) | `direct_ports` empty, high ports redirected, quarantine denies all |
| D-06 | A folded trip does publish `alert.updated` |

---

## DEF-005 (Low): the bind address is not validated before crossing to root

**Case:** C-06. **4 failing assertions.**

`PortForwardManager.add_forwards` validates ports thoroughly, rejecting zero,
negative, out-of-range, duplicate, self-mapped, and overlapping values. It does
not validate `bind_ip` at all. An empty string, `999.1.1.1`, `not-an-ip`, and an
IPv6 literal are all accepted and forwarded to the privileged helper.

**Repro**

```
.venv/bin/python -m pytest tests/functional/test_group_c_isolation.py::TestC06InvalidRulesRejected -p no:randomly
```

**Impact is limited, and this is not a hole.** The Swift helper does validate:
`buildPFRules` calls `isValidIPv4` on every address and throws, and the existing
"Rejects malformed rule data" and "IPv4 validation rejects ambiguous and
malformed forms" tests confirm it. No malformed rule reaches pfctl.

What is wrong is the shape. Ports fail fast in the sensor, addresses fail late
in a root process, which is an inconsistent boundary. `xpc.py:275` forwards the
payload unvalidated, and its `except Exception` turns the helper's specific
rejection into a generic "Failed to set up port forwards via helper", so the
operator sees no indication that an address was malformed.

**Code:** [port_forward.py:82](../sensor/src/squirrelops_home_sensor/network/port_forward.py)
validates ports but not `bind_ip`, [xpc.py:275](../sensor/src/squirrelops_home_sensor/privileged/xpc.py)
forwards as-is.

**Suggested direction.** Validate `bind_ip` alongside the port checks, so an
invalid address never crosses the privilege boundary and the error names itself.

---

## Group C notes

C-16 passes. The Linux sidecar rejects every malformed protected endpoint and
enforces its bounded-payload limits, which is the same job the Swift helper does
on macOS.

C-01, C-02, C-03, C-05, and C-07 needed no new tests. `PFIsolationTests.swift`
already covers them with 63 passing tests, including redirect-pass and
default-deny generation, ingress coverage, duplicate endpoint merging, and
malformed rule rejection.

**Process note.** The coverage review compared the plan against the *source*
surface and not against *existing test* coverage. That is why five Group C cases
were planned as new work when they were already covered. Later groups should
check the existing suites first.

---

## Group H notes, and a correction to my own coverage review

Group H produced no defects, and almost all of it was already covered.

| Planned case | Already covered by |
|---|---|
| H-01 two-phase scan | `single_scan_creates_devices_from_arp`, `single_scan_enriches_with_ports` |
| H-02 port-scan failure | `port_scan_failure_doesnt_block_devices` |
| H-04 ARP conflicts | `ip_conflicts_are_reconciled_before_device_filtering`, `same_mac_multi_ip_is_quarantined` |
| H-06 concurrency bound | `semaphore_limits_concurrent_connections` |
| H-07 per-port timeout | `unreachable_host_times_out`, `overall_scan_completes_in_bounded_time` |
| H-08 banner probing | 14 tests in `test_port_scanner_banners.py` |
| H-09, H-10 discovery | 8 mDNS browser and 17 SSDP tests |
| H-11, H-12 restart | `load_restores_devices`, `no_duplicate_db_rows_across_restart` |
| H-13 decoys excluded | `system_mimics_are_never_scanned_by_the_sensor` |

**The coverage review was wrong about this.** It recorded "whole `scanner/`
package untouched" as the single largest gap and justified adding 13 cases. The
package has 134 existing tests. That claim came from reading the source tree and
never opening the test tree, the same mistake that inflated Group C.

Two cases were genuinely missing and are now covered:

- **H-03.** `normalize_mac` had nine tests and none for the unpadded octet form
  macOS `arp -an` emits, such as `ae:29:a:e5:cc:c5`. That is a previously fixed
  defect in this project with no regression guard. The behavior is correct, and
  now it is pinned.
- **H-05.** Nothing asserted that `_local_interface_macs` returns normalized
  values. If it ever stopped, comparison against scan results would silently
  fail to match and the sensor would flag itself as an ARP conflict. Correct
  today, now pinned.

---

## Two false defects avoided

Recorded because a report-only suite is only worth reading if its failures are
trustworthy, and both of these failed first and looked real.

- **Hostname collision.** B-13 initially failed, appearing to show that a
  colliding mimic hostname was reused. The test had seeded `decoys` rows only.
  `_unique_generated_hostname` checks `decoy_hosts`, a different table, so no
  collision existed to detect. Test corrected, behavior is right.
- **Sensor hostname reuse.** A second B-13 case appeared to show the sensor's
  own hostname could be handed to a mimic. That guard lives in
  `_observed_real_hostnames`, not in the generator. The test was asserting
  against the wrong function. Corrected, and the guard is present.

Several other early failures were foreign-key errors from incomplete seeding,
notably `decoys.host_id` referencing `decoy_hosts` and `home_alerts.event_seq`
referencing `events`. All were test defects and none are reported here.

## Not yet run

132 of 164 planned cases. Groups A, C, E, F, H, I, J are unimplemented, plus
part of G. Nothing in this document should be read as a clean bill of health for
those areas. In particular the entire `scanner/` package, which is the sensor's
primary job, has no functional coverage yet.
