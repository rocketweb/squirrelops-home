# SquirrelOps Home: Defect Findings

Originally produced on `bugfix/decoy-status-defects` (off `origin/main` @ acf1cf4).
All confirmed fixes are now integrated on `hardening-and-bugfix-260810`.
Run date: 2026-08-07
Original policy: reported, not fixed. **DEF-002 through DEF-007 were
subsequently fixed at the maintainer's request.** DEF-001 is also integrated,
including the additional push-token and provider-switch remediation found in
the follow-up review.

**7 defects confirmed. 4 candidate findings investigated and rejected.**
116 automated assertions (15 fail, 101 pass) plus 9 live checks, across the full
product. The 15 failures are all reproductions of the 7 defects.

---

## Triage

Ordered by what to do first, not by discovery order.

| # | Sev | Defect | Effort | Notes |
|---|---|---|---|---|
| **DEF-001** | Critical | `GET /config` returns every stored credential | **fixed** | Responses fail closed, write-back preserves secrets, and vault persistence covers push tokens. |
| **DEF-002** | High | Rolling decoy-trip alerts notify once, then go silent | **fixed** | Embeds a behavior decision. See the note below. |
| **DEF-003** | Medium | Status read during registration invents a failure | **fixed** | Mapping now published before the mimic, three sites. |
| **DEF-007** | Medium | Unpadded MAC reaches a cloud LLM unredacted | **fixed** | Regex accepts one or two digits per octet. Audit still open. |
| **DEF-005** | Low | Bind address unvalidated before crossing to root | **fixed** | Validated beside the existing port checks. |
| **DEF-006** | Low | The app holds two definitions of a live mimic | **fixed** | `decoyDeviceIPs` now uses `isOperationalDeployment`. |
| **DEF-004** | Low | Unreachable branch weakens a default-deny | **fixed differently** | See the correction below. |

### DEF-002 embeds a behavior decision, please review it

An updated alert is now delivered only when its **visible summary changes**,
meaning severity or title, and at most once per 5 minute cooldown per alert.

Severity and title are the signal because they are what the alert row shows.
The title promotes to "Port scan detected from X" the moment a second endpoint
is touched, which is when the character of the event actually changed.
Delivering every update instead would turn a 1195-connection burst into 1195
notifications, which is worse than the silence it replaces.

The cooldown governs the gap **between re-notifications**, not the gap from the
original alert, so the first material change is never held back. That ordering
was wrong in the first implementation and the tests caught it.

Alternatives not taken: notify on every update (spam), notify on connection
count thresholds (arbitrary), notify only on severity increase (misses the
port-scan promotion, which is the most useful signal here).

### DEF-004 correction

The original write-up recommended deleting the unreachable `tcp pass` branch in
`buildPFRules`. **That recommendation was wrong.** The branch has twelve-plus
tests in `PFIsolationTests.swift` asserting its behavior, so it is a supported
helper capability, not dead code. Deleting it would have removed tested
functionality from the privileged helper.

The dead-ness is on the sensor side: `PortForwardManager` is the only producer
of `direct_ports` on either platform and hardcodes it empty. That is now a named
constant, `NO_DIRECT_PORTS`, carrying the reasoning, so the emptiness reads as a
decision rather than an oversight. An empty list literal said nothing about why.

**Cross-cutting:** DEF-007 is the third appearance of one wrong assumption. See
[The MAC padding assumption](#the-mac-padding-assumption).

---

# Defects

## DEF-001 (Critical): config endpoint returns every stored credential

**Case:** G-01. **5 failing assertions.**

`GET /config` returns the sensor configuration verbatim. Four secrets come back
in plaintext to any paired client:

| Secret | Config path |
|---|---|
| Home Assistant long-lived token | `home_assistant.token` |
| Slack incoming webhook URL | `alert_methods.slack.webhook_url` |
| Classifier API key | `classifier.llm_api_key` |
| Secret store passphrase | `sensor.secret_passphrase` |

`GET /config/alert-methods` returns the webhook as well.

**Impact.** The macOS app caches API responses through `URLCache`, which writes
them unencrypted to `~/Library/Caches/com.squirrelops.home/Cache.db`. That file
is mode 644 and owned by the user, so any process running as that user reads
every credential without ever holding the client certificate. Confirmed by
extraction on this machine during the session.

**Code:** [routes_config.py:270](../sensor/src/squirrelops_home_sensor/api/routes_config.py)
returns `config` directly.

**Status.** Fixed on `hardening-and-bugfix-260810`. Config responses are
non-cacheable and redacted, alert methods fail closed for unfamiliar fields,
and known credentials are removed from plaintext YAML persistence.

```
.venv/bin/python -m pytest tests/functional/test_known_defects.py::TestG01ConfigDoesNotReturnSecrets -p no:randomly
```

---

## DEF-002 (High): rolling decoy-trip alerts notify once, then go silent

**Case:** D-07. **1 failing assertion.**

`AlertDispatcher.subscribe_to` subscribes to `["alert.new"]` only.
`DecoyAlertHandler._create_or_update_trip_alert` folds every repeat trip from a
source into the existing unread alert and publishes `alert.updated`, which no
subscriber consumes.

D-06 passes and proves the event is published, so the gap is on the consuming
side, not the producing side.

**Impact.** An intrusion produces exactly one notification, on the first
connection. Observed live: alert 312 accumulated 1195 connections over 10 days
across 24 decoys and 31 endpoints, and sent one Slack message.

It also self-perpetuates. The fold-in query matches
`WHERE read_at IS NULL AND actioned_at IS NULL`, so an uncleared alert keeps
absorbing hits and can never fire again. Clearing it re-arms notification.

**Code:** [dispatcher.py:91](../sensor/src/squirrelops_home_sensor/alerts/dispatcher.py),
[decoy_handler.py:305](../sensor/src/squirrelops_home_sensor/alerts/decoy_handler.py)

**Why this needs a decision, not a patch.** Adding `alert.updated` to the
subscribe list would notify on every connection in a scan burst, which is worse
than silence. The fix has to define what an update notification means, most
likely re-notify on severity increase or on a newly seen endpoint, with rate
limiting.

```
.venv/bin/python -m pytest tests/functional/test_known_defects.py::TestD07UpdatedAlertsAreDelivered -p no:randomly
```

---

## DEF-003 (Medium): status read during registration invents a failure

**Case:** B-09. **1 failing assertion.**

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

**Impact.** Transient false DEGRADED in the Scouts screen. Cosmetic, but it
erodes trust in the one screen meant to report deception health, and the silent
`.get(decoy_id, decoy_id)` default makes a genuinely missing mapping
indistinguishable from a real failure.

**Code:** [orchestrator.py:231](../sensor/src/squirrelops_home_sensor/scouts/orchestrator.py),
sites at 1393, 3114, 3826.

**Suggested direction.** Populate the mapping before publishing into
`_active_mimics`, so no await separates them. Three sites, no other behavior
change. Separately, consider making the missing-mapping case explicit rather
than defaulting.

**Caveat.** This reproduces the mechanism. It does **not** prove it caused the
mixed-status screenshot from 2026-08-03, whose decoy rows no longer exist. That
screenshot showed 3 active and 2 degraded on one host, whereas this race
predicts 1 active with the rest degraded. Either a second cause exists or the
screenshot caught a different transition.

```
.venv/bin/python -m pytest tests/functional/test_known_defects.py::TestB09NoFalseDegradedDuringRegistration -p no:randomly
```

---

## DEF-007 (Medium): unpadded MAC reaches a cloud LLM unredacted

**Case:** G-07. **1 failing assertion.**

`_sanitize_signal` strips addresses out of device signals before they are sent to
a cloud classifier. It misses the unpadded MAC form:

```
_sanitize_signal("host AE:29:A:E5:CC:C5 here")  ->  unchanged
_sanitize_signal("host AE:29:0A:E5:CC:C5 here") ->  redacted
```

**Cause.** `_FULL_MAC_RE` requires exactly two hex digits per octet:

```python
(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}
```

The IPv4 pattern beside it is written flexibly as `\d{1,3}`, so the rigidity is
specific to the MAC branch. The IPv6 candidate pattern does match the string,
but `_redact_ipv6` only redacts what `ipaddress` parses as real IPv6, and a
six-group MAC does not parse, so it is returned unchanged.

**Impact.** `_sanitize_signal` is applied to values the code explicitly labels
untrusted: DNS hostname, mDNS hostname, and other device-supplied strings at
llm_classifier.py lines 176, 182, and 212. A device on the LAN chooses its own
mDNS hostname. Advertising one containing an unpadded MAC puts that address
verbatim into an outbound prompt to a third-party API.

The stored `mac_oui` goes through `normalize_mac` first and is padded, so the
primary path is safe. This is the untrusted-input path, which is the one the
control exists for.

**Code:** [llm_classifier.py:62](../sensor/src/squirrelops_home_sensor/devices/llm_classifier.py)

**Suggested direction.** Allow one or two hex digits per octet in the MAC
branch, or run untrusted values through `normalize_mac` before matching. Then
see the cross-cutting note below.

```
.venv/bin/python -m pytest tests/functional/test_group_gij.py -p no:randomly
```

---

## DEF-005 (Low): bind address unvalidated before crossing to root

**Case:** C-06. **4 failing assertions.**

`PortForwardManager.add_forwards` validates ports thoroughly, rejecting zero,
negative, out-of-range, duplicate, self-mapped, and overlapping values. It does
not validate `bind_ip` at all. An empty string, `999.1.1.1`, `not-an-ip`, and an
IPv6 literal are all accepted and forwarded to the privileged helper.

**This is not a hole.** The Swift helper does validate: `buildPFRules` calls
`isValidIPv4` on every address and throws, confirmed by the existing "Rejects
malformed rule data" and "IPv4 validation rejects ambiguous and malformed forms"
tests. No malformed rule reaches pfctl.

What is wrong is the shape. Ports fail fast in the sensor, addresses fail late
in a root process, which is an inconsistent boundary. `xpc.py:275` forwards the
payload unvalidated, and its `except Exception` turns the helper's specific
rejection into a generic "Failed to set up port forwards via helper", so the
operator sees no indication that an address was malformed.

**Code:** [port_forward.py:82](../sensor/src/squirrelops_home_sensor/network/port_forward.py)
validates ports but not `bind_ip`,
[xpc.py:275](../sensor/src/squirrelops_home_sensor/privileged/xpc.py) forwards as-is.

**Suggested direction.** Validate `bind_ip` alongside the port checks, so an
invalid address never crosses the privilege boundary and the error names itself.

```
.venv/bin/python -m pytest tests/functional/test_group_c_isolation.py::TestC06InvalidRulesRejected -p no:randomly
```

---

## DEF-006 (Low): the app holds two definitions of a live mimic

**Case:** E-03. **1 failing assertion.**

`DecoySummary` states the rule explicitly:

```swift
public var isOperationalDeployment: Bool {
    status == "active" || status == "degraded"
}
```

`AppState.decoyDeviceIPs`, which decides what gets hidden from the device
inventory, disagrees:

```swift
guard decoy.decoyType == "mimic", decoy.status == "active" else { return nil }
```

A degraded mimic keeps its `lo0` alias. When the degradation is a failed mDNS
registration the listener is running normally, so the address is live but the
app would not recognise it as a fake host.

**Impact is limited today.** The sensor filters first, and its filter has a
second clause the app does not:

```sql
AND NOT EXISTS (
    SELECT 1 FROM virtual_ips vip
    WHERE vip.ip_address = d.ip_address AND vip.released_at IS NULL
)
```

An unreleased `virtual_ips` row covers a degraded mimic regardless of decoy
status, so no device row reaches the app in the ordinary path.

**Why it still matters.** The app filter is the second line of defence, and it is
the line with the hole. If a device row ever did arrive for a degraded mimic
address, through a WebSocket device event racing deployment or any future change
to the sensor filter, the app would render one of its own fake hosts to the user
as a real device. That is the specific outcome the filter exists to prevent.

**Code:** [AppState.swift:143](../app/Sources/SquirrelOpsHome/State/AppState.swift),
[Models.swift:842](../app/Sources/SquirrelOpsHome/Networking/Models.swift),
[decoy_filter.py:7](../sensor/src/squirrelops_home_sensor/devices/decoy_filter.py)

**Suggested direction.** Have `decoyDeviceIPs` use `isOperationalDeployment`
rather than its own inline status check, so the two definitions cannot drift.

```
swift test --filter FunctionalGroupE
```

---

## DEF-004 (Low): unreachable branch weakens a default-deny

**Case:** C-04. **Characterized by 3 passing tests.**

Not a behavior defect. The PF rules are correct and the tests confirm it:
`direct_ports` is empty from both macOS call sites, every advertised port is
redirected through `rdr pass`, and high ports get no special treatment.

The finding is that `buildPFRules` carries a
`pass in quick ... proto tcp ... port { … }` branch no macOS caller can reach,
because `direct_ports` is hardcoded empty at
[port_forward.py:158](../sensor/src/squirrelops_home_sensor/network/port_forward.py)
with a comment explaining that directly allowing a virtual-IP port would let a
wildcard-bound host daemon answer on the decoy address.

**Impact.** Dead code that, if ever fed a non-empty list, would punch exactly the
hole the comment forbids. Low severity today, latent risk.

**Code:** [RPCMethods.swift:1486](../app/Sources/SquirrelOpsHelper/RPCMethods.swift)

**Before removing:** check `privileged/linux_sidecar.py`, which also accepts
`direct_ports` and may legitimately use it.

---

# The MAC padding assumption

DEF-007 is not an isolated bug. macOS `arp -an` emits unpadded octets
(`ae:29:a:e5:cc:c5`), and code that assumes two hex digits keeps breaking on it.
Three independent hits in a single session:

| Where | Outcome |
|---|---|
| `normalize_mac` | Handles it correctly, but had **no regression guard** until H-03 added one |
| `qa/live/check.sh` F-09 | My own script hit it and falsely reported 10 host collisions |
| `_FULL_MAC_RE` | **DEF-007**, an actual defect |

Three hits from three directions suggests the assumption is worth auditing
project-wide rather than patching one site. Any comparison, regex, or lookup
that consumes a MAC from a system tool rather than from `normalize_mac` is a
candidate.

---

# Investigated and rejected

Recorded because a report-only suite is only worth reading if its failures are
trustworthy. All four failed first and looked real.

| Candidate | Why it was rejected |
|---|---|
| Colliding mimic hostname reused | Test seeded `decoys` rows only. `_unique_generated_hostname` checks `decoy_hosts`, a different table, so no collision existed to detect. Behavior is correct. |
| Sensor hostname available to a mimic | The guard lives in `_observed_real_hostnames`, not the generator. Test asserted against the wrong function. Guard is present. |
| 10 virtual IPs colliding with a foreign host | `qa/live/check.sh` compared `arp -n` output against `ifconfig` without normalizing. The "foreign" MAC was the Mac's own. Script fixed. |
| Log directory world-readable at mode 700 | `stat -f '%Lp'` prints octal and bash arithmetic read `700` as decimal, where bit 2 is set. Script fixed with `8#$mode`. |

Several other early failures were foreign-key errors from incomplete seeding,
notably `decoys.host_id` referencing `decoy_hosts` and `home_alerts.event_seq`
referencing `events`. All were test defects and none are reported here.

Had the four above been reported rather than investigated, this document would
carry seven real defects and four fabricated ones, with no way to tell them
apart.

---

# Coverage record

## What ran

| Group | Planned | New assertions | Result |
|---|---|---|---|
| Known defects | 7 | 14 | 9 fail, 5 pass |
| D, alert pipeline | 12 | 14 | all pass |
| B, mimic lifecycle | 13 | 13 | all pass |
| C, isolation and PF | 12 | 27 | 4 fail, 23 pass |
| H, scanning | 13 | 6 | all pass |
| A, API surface | 43 | 15 | all pass |
| E, app behavior | 22 | 9 | 1 fail, 8 pass |
| G, security | 12 | 18 | 1 fail, 17 pass |
| I, data layer | 8 | 0 | already covered |
| J, device intelligence | 8 | 0 | already covered |
| F, live system | 13 | 14 checks | 9 pass, 5 need root |

**Totals: 116 automated assertions, 15 fail, 101 pass, plus 9 live checks.**
The full sensor suite runs 1934 passed with the same failures, so the functional
cases introduced no regressions.

## Already covered, so not rewritten

The plan's 164 cases collapsed to roughly 40 genuinely new ones once checked
against the existing suites.

| Area | Existing coverage found |
|---|---|
| PF rule builder | 63 tests in `PFIsolationTests.swift` |
| Scanner package | 134 tests across 6 files |
| API surface | 259 tests across `test_routes_*.py`, `test_ws.py`, api_auth |
| App behavior | 281 tests in `SquirrelOpsHomeTests` |
| Data layer and device intelligence | 200-plus tests |

## Deliberately not covered

- **SwiftUI view bodies.** Rendering is not meaningfully unit-testable here. The
  state each view derives from is covered instead.
- **`HelperManager`, `SensorInstaller`.** Both install or inspect a privileged
  helper on the real system, so exercising them would mutate the machine. They
  need a fixture that fakes the install root first.
- **`linux_sidecar.py` PF path.** Out of scope for a macOS install, but flagged
  under DEF-004 because `direct_ports` may be live there.
- **Live network scanning.** Group H uses fixtures. A live scan would be
  non-deterministic and would touch neighbouring devices.

## Live checks needing root

F-05, F-06, F-08, F-10, and F-11 read the sensor database and are skipped rather
than prompting. Run the whole script with root to execute them:

```
sudo bash qa/live/check.sh
```

---

# Method notes

Two corrections to the coverage review, both recorded because they changed how
much of the plan was real work.

**The review checked the source tree, not the test tree.** It named "whole
`scanner/` package untouched" as the single largest gap and justified 13 cases.
The package has 134 existing tests, and 11 of the 13 were already covered, often
by tests with near-identical names. The same mistake inflated Group C by 5 cases.
Once corrected, Group A produced 6 new cases instead of 43.

**Worth keeping regardless of the correction:** A-42, a systematic
authentication sweep. It reads every path and method from the OpenAPI schema,
subtracts the deliberately unauthenticated ones, and asserts each remaining
route answers 401 or 403 without a client certificate. Authentication was five
point tests over a 53-endpoint surface. The sweep covers 30-plus routes and will
cover any route added later without anyone remembering to write a test. It
passes.

Also newly pinned, all passing, all previously unguarded: `normalize_mac`
zero-padding (H-03), `_local_interface_macs` normalization (H-05), and
`SensorAPICompatibility` (E-14), the gate that refuses a sensor speaking a
different API protocol and had no tests at all.
