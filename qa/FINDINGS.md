# SquirrelOps Home: Defect Findings

Branch: `bugfix/decoy-status-defects` (off `origin/main` @ acf1cf4)
Run date: 2026-08-07
Policy: **reported, not fixed.** No product code was changed.

## Execution status

| Group | Cases planned | Implemented | Run | Result |
|---|---|---|---|---|
| Known defects (B-08, B-09, C-04, D-06, D-07, G-01, G-02) | 7 | 14 assertions | yes | 9 fail, 5 pass |
| A, remainder of B, C, D, E, F, G, H, I, J | 157 | not yet | no | pending |

`sensor/tests/functional/test_known_defects.py`, run with
`.venv/bin/python -m pytest tests/functional/ -p no:randomly`.

**9 failed, 5 passed.** Every failure below is a reproduction, not a broken
test. The 5 passes are the control cases that show the assertions are sound.

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

## Not yet run

157 of 164 planned cases. Groups A, E, F, H, I, J are unimplemented, as is most
of B, C, D, and G. Nothing in this document should be read as a clean bill of
health for those areas.
