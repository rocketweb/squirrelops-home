# Documentation claim verification, October 2, 2026

The original feature list overstated the decoy protocols, behavioral monitoring,
credential detection, and APNs readiness. Current documentation now describes
the implemented runtime and marks incomplete capabilities explicitly.

## Source and scope

- Worktree: `.worktrees/deception-depth-2.1-current`.
- Branch: `feature/ai-setup-2.1`.
- Source baseline: `7a7b3d072f818215c8fd9b4573d287e63d068203`.
- The [post-merge follow-up](2026-10-02-documentation-post-merge.md) records
  transfer to the merged 2.1 source and the checks performed there. The full
  suite and guest results below retain their original baseline.
- Reviewed current README, operator/development/security/release guides, AI and
  deep-deception specifications, guest README, 2.1 candidate notes, in-app help,
  and static download-page copy against source and tests.
- Earlier release notes, security audits, QA plans, and dated acceptance records
  remain historical evidence. They are not current feature guarantees. The old
  QA plan now says this explicitly. Historical live runners were not reused.

This is an implementation and local-test audit. It does not certify every
historical assertion, every device on a LAN, provider availability, or release
readiness. No installed service, PF rule, real Home Assistant configuration,
cloud AI account, notification endpoint, or update-channel manifest was changed.

## The eleven original claims

**Verified** means source and local checks support the stated capability.
**Qualified** means a narrower statement is supported. **Unsupported** means
the advertised end-to-end behavior is absent from this runtime.

| Original claim | Status | What exists and what changed |
| --- | --- | --- |
| Honeypots that blend in | Qualified | Classic selection uses observed dev/HA/SMB/AFP ports and a file-directory fallback. These are selected HTTP presentations, not deployed Express, nginx, file-sharing, or Home Assistant installations. [Selection](../../sensor/src/squirrelops_home_sensor/decoys/orchestrator.py) and [classic protocol tests](../../sensor/tests/integration/test_decoy_orchestrator.py). |
| Squirrel Scouts | Verified with limits | Observed profiles are grouped by source; unique observed ports become separate service rows with a shared virtual IP and hostname. Fidelity is bounded HTTP sampling, banners, local TLS identity, and mDNS. Capacity, source eligibility, and privileged publication must succeed. [Templates](../../sensor/src/squirrelops_home_sensor/scouts/templates.py), [orchestration](../../sensor/src/squirrelops_home_sensor/scouts/orchestrator.py), [tests](../../sensor/tests/integration/test_mimic_orchestrator.py). |
| Studio Build Mac | Qualified | Real OpenSSH/SFTP and Samba run in a memory-only Linux guest with macOS-shaped content. No virtual NIC or host directory is attached. The model/MCP presentations are synthetic sensor listeners. Both opt-in real-guest tests passed locally. This requires the runtime, guest bundle, eligible profile, helper, and publication checks. [Guest boundary](../SECURITY_MODEL.md#disposable-guest), [live protocol test](../../sensor/tests/integration/test_deep_deception_live_guest.py). |
| High-confidence decoy alerts | Qualified | Unexpected activity is High and recognized credential submission is Critical. A connection can come from an operator or legitimate scanner. Exact automatic IPP discovery is retained without an intrusion alert. Behavioral definitions are separate, but no active baseline producer exists. [Handler](../../sensor/src/squirrelops_home_sensor/alerts/decoy_handler.py), [tests](../../sensor/tests/integration/test_decoy_alert_handler.py). |
| Device fingerprinting identifies every device using DHCP and other signals | Unsupported as written | Active ARP, selected TCP probes, OUI, mDNS/SSDP or HA enrichment, and optional AI classification exist. Sleeping, unreachable, or other-segment devices can be missed; classification is heuristic. DHCP signature support exists but production scans do not collect DHCP. [Scan loop](../../sensor/src/squirrelops_home_sensor/scanner/loop.py), [startup](../../sensor/src/squirrelops_home_sensor/__main__.py), [fingerprint matching](../../sensor/src/squirrelops_home_sensor/fingerprint/matcher.py). |
| Believable decoy naming | Verified | Deterministic ordinary names and optional hostname-pattern AI suggestions exist. New-batch AI suggestions cover half rounded up, with local validation and fallback. [Naming implementation](../../sensor/src/squirrelops_home_sensor/scouts/orchestrator.py), [configuration and prompt contract](../AI_DEVICE_CLASSIFICATION_AND_DECOY_NAMING.md). |
| Automatic 48-hour behavioral baselines and anomaly alerts | Unsupported | Collector/detector classes, database support, configurable duration, and progress UI exist. Learning is disabled by default; startup does not collect connection destinations, invoke the collector/detector, or automatically start/finish training. Documentation now advertises active scan-based security insights instead. [Standalone baseline](../../sensor/src/squirrelops_home_sensor/devices/baseline.py), [startup](../../sensor/src/squirrelops_home_sensor/__main__.py), [learning API](../../sensor/src/squirrelops_home_sensor/api/routes_system.py). |
| Seven credential-canary formats trigger Critical when accessed | Qualified | The generator supports seven formats; deployment uses subsets. Bait-file retrieval is ordinary decoy activity. Recognized values submitted in supported headers/bodies can be Critical. Individual keys inside a generated `.env` are not guaranteed to match. SSH/SMB relays cannot recognize authentication or file access. [Generator](../../sensor/src/squirrelops_home_sensor/decoys/credentials.py), [mimic handler](../../sensor/src/squirrelops_home_sensor/decoys/types/mimic.py), [guest relay](../../sensor/src/squirrelops_home_sensor/decoys/deep/orchestrator.py). |
| Inventory, alerts, and configuration all stay in local SQLite | Qualified | Inventory, alerts, and evidence use SQLite. Non-secret configuration uses YAML; real operator credentials use the encrypted secret store; app pairing uses Keychain. Optional cloud classification and external delivery require configuration. [Configuration](../../sensor/src/squirrelops_home_sensor/config/__init__.py), [secret handling](../../sensor/src/squirrelops_home_sensor/api/config_secrets.py), [privacy guide](../USER_GUIDE.md#privacy--security). |
| APNs alerts to iPhone/Mac | Unsupported as a shipped workflow | Sensor APNs sender and relay code exist and are fixture-tested. App remote-token registration and an iPhone client do not exist here. Manual relay/token configuration is an infrastructure path, not a ready Settings feature. Native Mac notifications and optional Slack are implemented. [Dispatcher](../../sensor/src/squirrelops_home_sensor/alerts/dispatcher.py), [relay](../../relay/api/push.ts), [native notifications](../../app/Sources/SquirrelOpsHome/Desktop/MacNotificationService.swift). |
| HA enriches names, areas, and types | Qualified | HA devices with MAC connections are matched to inventory and supply names, areas, manufacturer, and model. The registry client does not supply a general device-type field. HA destinations are restricted to validated private-LAN addresses. [Client](../../sensor/src/squirrelops_home_sensor/integrations/home_assistant.py), [enrichment](../../sensor/src/squirrelops_home_sensor/devices/manager.py), [client tests](../../sensor/tests/unit/test_home_assistant_client.py). |

## Actual decoy depth

| Decoy | Implemented surface | Limits |
| --- | --- | --- |
| File Share | Python HTTP directory listing, password file, RSA private-key bait, nginx-style banner | No classic SMB/AFP service or nginx process. |
| Dev Server | Static React-style page, `/api/health`, `/.env`, Express-style header | No React build/dev process, Express, Next.js, or Flask server. |
| Home Assistant | Static login form, `/api/` error, `/auth/token` rejection, generated token detector | No HA installation, authenticated session, or device API. The token is not inserted into the fixed login/error routes. |
| Generic Scout mimic | Per-port HTTP samples or protocol banners, fake-host certificate, mDNS identity | No full SSH handshake/shell or general SMB/database protocol implementation. Bait is added as text-file routes to one eligible HTTP service; no eligible HTTP service means no planted bait. |
| Studio Build Mac | Real SSH/SFTP and Samba, writable synthetic shares, Linux shell with Mac-shaped commands/files | Underlying Linux can be fingerprinted. Guest relay evidence records connections/outcomes, not logins, commands, reads, or writes. |
| Studio AI/MCP | Synthetic model lists, chats, tools, project/runbook data, source-specific narrative | No inference or real tool execution. HTTP/MCP write-like requests can advance the narrative; guest SMB writes do not. |
| Studio Time Machine share | Samba Apple extensions and a writable `Time Machine Backups` share | Complete macOS backup and restore acceptance remains unverified. |

Classic protocol checks are in [File Share](../../sensor/tests/integration/test_file_share_decoy.py),
[Dev Server](../../sensor/tests/integration/test_dev_server_decoy.py), and
[Home Assistant](../../sensor/tests/integration/test_home_assistant_decoy.py).
Generic mimic checks are in [server tests](../../sensor/tests/unit/test_mimic_server.py)
and [template tests](../../sensor/tests/unit/test_mimic_templates.py).
Synthetic AI/MCP routes are covered by [workbench tests](../../sensor/tests/integration/test_ai_workbench_decoy.py).

## Other documentation corrections

- Removed automatic new-device, MAC-change/verification, rejected-device
  reappearance, vendor-advisory, learning-complete, and review-reminder alerts
  from the list of active runtime promises. Definitions/events or standalone
  classes do not establish an alert-feed producer. Trust status remains saved
  operator state.
- Corrected the app's five-minute disconnected alert to Medium, local to the
  app, rather than a Low sensor-persisted alert.
- Corrected the in-app Scout help. Scouts probes within the sensor; there is
  no remote-agent enrollment or revocation workflow.
- Clarified that active incidents and linked alerts can outlive the default
  90-day retention age.
- Corrected claims that payloads are never inspected or only fake credentials
  are stored. HTTP decoys inspect requests; configured real service keys are
  retained in the encrypted store.
- Corrected remote pairing to HMAC/HKDF plus certificate enrollment, while
  packaged local pairing uses the signed XPC helper and a Keychain-backed key.
- Distinguished partial generic mimics from Studio's real guest protocols,
  and described missing guest artifacts as unavailable/degraded.
- Removed the promised automatic three-crash/30-minute health cycle. Classic
  `check_health`/`check_degraded` methods are not scheduled by startup. Saved
  degraded classic rows are retried by scan-driven `auto_deploy` instead.
- Narrowed unconditional certificate and traffic-safety promises to the
  implemented certificate pin, mutual-TLS key proof, and decoy-scoped forwarding.
- Repaired fixed-width README and helper diagrams. Every row now has consistent
  wall positions. The README diagram also names the active deep-decoy runtime
  instead of the inactive behavioral baseline.
- Split Home package verification from future Sensor installer/OCI verification.
  Their signer workflows and artifact sets differ; Linux publication is blocked.
- Replaced the stale README installer example with verified Home 2.0.3 release
  provenance, and distinguished development 2.1 from the published package.
- Removed Linux installation promises and unconditional local-data wording from
  the static site. Its badge/button now explicitly follow the update channel;
  the fallback URL pins its actual tag instead of mixing `latest` with an old
  package filename.

## Verification performed

| Check | Result |
| --- | --- |
| Focused sensor feature checks, before full suite | 747 passed. The initial sandbox denied local socket binds; the same checks passed with local networking permitted. |
| Full sensor suite | 2,454 passed, 3 opt-in skips, 3 dependency warnings; 89.55 seconds. |
| Full native suite from a fresh scratch directory | App 400, helper 121, guest runtime 30 passed. |
| Native desktop tests after help-text edits | 9 passed; app rebuilt successfully. |
| Two opt-in real-guest integration tests | 2 passed; 41.99 seconds. |
| Documentation acceptance fixtures | 369 ran, 365 passed, 4 explicit skips. Uses synthetic inputs and available retained evidence; no live runner executed. |
| Published Home 2.0.3 | `gh release verify` passed; verification document attestation passed against the exact workflow/commit/ref. Downloaded document SHA-256 matches the release asset record. |
| Diagram and download copy | Browser-rendered locally and visually inspected; fixed diagram walls, pinned fallback, unchanged manifest parity, and no page overflow at 1920 and 390 pixels confirmed. |

Full sensor command:

```sh
cd sensor
.venv/bin/python -m pytest tests/ -q --tb=short
```

Native command on this macOS 27 development host:

```sh
cd app
DEVELOPER_DIR=/Library/Developer/CommandLineTools swift test \
  --sdk /Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk \
  --scratch-path .build/claims-verification \
  -Xswiftc -plugin-path \
  -Xswiftc /Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing
```

The guest test used the freshly compiled native runtime, ad-hoc signed with
only the virtualization entitlement, and the existing architecture-matched
guest bundle. It passed authenticated SSH with persona commands, SFTP and SMB
file roundtrips, synthetic SMB identity, loopback-only guest networking,
host-canary isolation, slot limits, half-close/reconnect behavior, and shutdown.
These are loopback tests, not installed LAN/PF or default-filter acceptance.

```sh
cd sensor
SQUIRRELOPS_DECEPTION_RUNTIME=../build/test-artifacts/claims-guest/com.squirrelops.deception-guest \
SQUIRRELOPS_GUEST_BUNDLE=../guest/studio-mini/build/arm64 \
  .venv/bin/python -m pytest \
  tests/integration/test_deep_deception_live_guest.py \
  tests/integration/test_guest_resolver_live.py -q --tb=short
```

Fixture command:

```sh
sensor/.venv/bin/python -m unittest discover \
  -s docs/testing/fixtures -p 'test_*.py'
```

Local logs, attestation JSON, and browser screenshots are retained under ignored
`build/test-artifacts/claims-*`. They are not public release assets.

## Publication and remaining limits

Read-only GitHub checks on October 2 found the latest immutable Home release
[2.0.3](https://github.com/rocketweb/squirrelops-home/releases/tag/home-v2.0.3)
and no `home-v2.1*` tag. Its verified source commit is
`eb2d87af5e24d924204afb4f2c0bcbd7403ac559`. The package digest in release metadata
matches GitHub's asset record:
`252bd6bd559b4dbf578410aa959611675d3b627163ee885f404857cb67ab23f8`.
The package was not downloaded, installed, signature-checked, or notarization-checked
in this audit; the attested instructions explain those independent checks.

The checked-in website manifest still advertises 1.1.14. Updating that machine
update channel requires the separate promotion review described in
[Release security](../RELEASE_SECURITY.md#post-release-website-manifest).
This documentation change does not promote it or deploy the static page.

Real cloud-provider classification, a configured real HA registry, APNs delivery
to an actual Apple client, macOS notification permission/banner acceptance,
complete Time Machine backup/restore, and the remaining live PF failure cases
were not exercised. Fixture or unit tests establish implemented contracts, not
those external end-to-end outcomes. Final 2.1 signed-installer acceptance,
independent review, CI, and publication remain separate gates in the
[publication-readiness record](2026-10-01-publication-readiness.md).

No decoy behavior, attacker-visible response, signing policy, release control,
commit, push, deployment, tag, or publication changed during this audit.
