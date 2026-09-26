# SquirrelOps Home 2.1 local decoy functional test report

Test date: September 4, 2026. Functional testing began at 11:48 EDT on Matt's Mac Studio. Individual result timestamps are retained; JSON evidence uses UTC.

## Verdict

**Partial acceptance. The available local testing round is complete, but the running installation does not pass full 2.1 end-to-end acceptance.**

- The installed Network Share works end to end: HTTP requests reached the running sensor, all 10 appeared in its forensic log, and synthetic credential reuse produced two Critical alerts and two credential trips.
- Real SSH, SFTP, and SMB worked in a disposable guest booted from the installed app's runtime and guest bundle. Authentication, all three SMB shares, file operations, containment checks, concurrency, stop, and restart passed.
- Studio Build Mac was absent from the running app. No persistent guest process or former `192.168.1.203` alias was present. The successful disposable guest tests do **not** establish that the installed sensor publishes this host or receives its LAN traffic.
- Installed-code regression tests: **464 passed, 3 failed**. The failures concern newer alert-evidence fields absent from this older installation. The same three tests passed against the committed candidate source.
- Two AI streaming fidelity checks failed. The live file-share SSH-key bait also failed a normal PEM parser check.

No fixes, installation, sensor restart, networking changes, commit, or release were performed.

## Scope and identity

The engineering-constraints skill was used to keep installed behavior, isolated artifact tests, source regressions, and unverified LAN behavior separate. No product implementation was changed.

| Item | Observed value |
| --- | --- |
| Host | Mac Studio, arm64, macOS 26.6.2, build 25G83 |
| Running app | `/Applications/SquirrelOps Home.app`, version 2.1.0, PID 33865 |
| Running sensor | `/Library/SquirrelOps/sensor/python/bin/python3`, `_squirrelops`, PID 31785 |
| Helper | `/Library/PrivilegedHelperTools/com.squirrelops.helper`, PID 31777 |
| Candidate checkout | `/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current` |
| Candidate branch | `feature/deception-depth-2.1.0-current` |
| Candidate commit | `6b6ef8b5fe3d694695a9bc74982cbe80d05baeb5` |
| Local sensor address | `192.168.1.18` |
| Installed app binary SHA-256 | `e5d05180351fb66dc87e9ecdccf315f5a4b6841430e4bcf2ee60c944147995be` |
| Existing newer installer SHA-256 | `212c493cec3a995603ee0cd19f0712b6df99aa289d3afa837f60f5aaf14259b0` |

The newer installer is [SquirrelOpsHome-2.1.0-alert-evidence-local-test.pkg](/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/build/test-artifacts/SquirrelOpsHome-2.1.0-alert-evidence-local-test.pkg). Its checksum was rechecked, but it was not installed during this session. Both builds use the marketing version 2.1.0, so that version alone cannot identify the tested code.

The installed alert handler has a September 1 source-file timestamp and lacks `_MAX_RECENT_CONNECTIONS`, `service_counts`, and `recent_connections`. Its behavior and regression failures confirm that the newer alert-evidence implementation is not installed. This report is not acceptance of the newer installer.

### Test layers

1. **Running installation:** native app inspection, owned listener probes, actual file-share requests, real alert delivery and forensic counters.
2. **Installed artifacts in disposable fixtures:** installed guest runtime/bundle and installed Python modules, with loopback-only listeners, generated synthetic data, and an in-memory test database. These did not use the running sensor's alert pipeline.
3. **Regression tests:** candidate test files importing the installed sensor modules first. One separately labeled comparison imported candidate source.

Only verified local SquirrelOps endpoints were contacted. No LAN-wide scan or connection to unrelated devices was performed.

## Running installation and inventory

| Check | Result | Evidence |
| --- | --- | --- |
| App code-signature integrity | PASS | `codesign --verify --deep --strict --verbose=2` exited successfully. This is not a fresh notarization check. |
| Installed ARM64 guest-bundle validation | PASS | `scripts/verify-guest-bundle.py --architecture arm64` accepted the installed bundle. |
| Sensor health | PASS | `/system/health` returned HTTP 200, `status: ok`; uptime approximately 259,636 seconds. |
| API without client certificate | PASS | `/system/status`, `/alerts`, and `/decoys` returned 403, `Valid client certificate required`. Authentication was not bypassed. |
| Native app navigation | PASS | Decoys, Alerts, Review, detail sheets, severity filters, and History were inspected after the app was foregrounded. |
| Studio Build Mac availability | NOT ACCEPTED | Missing from inventory; no installed guest process and no `.203` alias. Startup cause remains unverified. |
| Bonjour observation | LIMITED | Four-second windows saw the sensor service but no SSH or SMB record for Studio. A bounded local browse is not a LAN-discovery proof. |

The Decoys view reported **8 fake hosts, 25 service decoys, and 1 host listener**:

| Fake host | Virtual IP | Services | Displayed historical hits |
| --- | --- | ---: | ---: |
| business.local | 192.168.1.200 | 2 | 0 |
| docs.local | 192.168.1.201 | 1 | 0 |
| media.local | 192.168.1.204 | 7 | 3 |
| shared.local | 192.168.1.206 | 3 | 7 |
| office-nas.local | 192.168.1.212 | 7 | 509 |
| office-printer.local | 192.168.1.216 | 3 | 374 |
| financials | 192.168.1.243 | 1 | 13 |
| runner | 192.168.1.244 | 1 | 11 |

These historical hits are inventory context, not new successful test connections. Visible service cards were labeled ACTIVE. The separate Network Share host listener was ACTIVE at `192.168.1.18:63219`, decoy ID 3.

### Same-host mimic probes

The 25 private backend listeners were associated with sensor PID 31785 before probing. Every direct connection from this Mac timed out. The host listener at `192.168.1.18:63219` connected and returned HTTP 200.

Do **not** interpret the 25 timeouts as proof of 25 broken decoys. The helper's PF construction intentionally blocks direct backend access and admits advertised ports through physical-interface redirection. Same-host direct-backend probes do not reproduce that path. The relevant implementation is `app/Sources/SquirrelOpsHelper/RPCMethods.swift`, including the default-deny explanation near line 1487 and the final block rule near line 1565.

Live PF rules could not be inspected with available privileges. Advertised-port ingress and source attribution from a second LAN machine remain **unverified**. The old `.203` address was not assumed to still be a valid target.

## Live Network Share and alert pipeline

Target: `http://192.168.1.18:63219`. All credentials came from this decoy's synthetic password file and were kept out of saved evidence.

| ID | Action | Result | Observed evidence |
| --- | --- | --- | --- |
| H00 | Initial directory request | PASS | HTTP 200, `Server: nginx/1.24.0`; High alert at 11:49:53. |
| H01 | Two more directory requests | PASS | Both HTTP 200 with nginx-style index and password-file link. |
| H02 | Read `/passwords.txt` | PASS | HTTP 200; eight synthetic credential entries. Reading the file alone did not increment credential trips. |
| H03 | Read `/.ssh/id_rsa` and parse | FAIL: fidelity | HTTP 200, but `load_pem_private_key` raised `ValueError`. Source confirms random bytes inside RSA PEM delimiters, not a valid key. |
| H04 | Request a nonexistent QA path | PASS | HTTP 404; request still appears in the forensic connection log. |
| H05 | Fetch a synthetic credential for reuse | PASS | Credential read into memory from the same decoy. |
| H06a | Submit it using Basic authentication | PASS | HTTP 200; one credential-trip log entry. |
| H06b | Submit it using Bearer authentication | PASS | HTTP 200; a second credential-trip log entry. |
| H06c | Submit malformed Basic authentication | PASS | HTTP 200; no third credential trip, service remains responsive. |

Counter reconciliation:

| Point | Connections | Credential trips | UI evidence |
| --- | ---: | ---: | --- |
| After initial probe | 1 | 0 | High connection alert |
| After five browse-phase requests | 6 | 0 | New High connection alert at 11:55:59 |
| After four credential-phase requests | 10 | 2 | Two Critical alerts at 11:58:51 |
| Final detail inspection | 10 | 2 | 10 forensic rows, two CREDENTIAL badges, password file TRIPPED, failures 0 |

The Critical detail showed source `192.168.1.18`, TCP port `63219`, path `/`, detection `HTTP Decoy`, and Network Share decoy ID 3. It also showed the matched synthetic credential, which is redacted from this report.

Critical filtering displayed the two credential alerts. Opening one marked it read; History retained it. High filtering displayed both current-test High alerts along with older history. No history was deleted. Two test alerts remained unread at the end.

The older installed UI categorized the single-endpoint connection alert as **Port scan detected** and lacked the newer count/service timeline evidence. A grouped alert is not evidence that subsequent requests were lost: the decoy detail retained all 10 requests.

## Real SSH, SFTP, and SMB from installed artifacts

These tests booted the installed root-owned guest runtime and installed guest bundle under a disposable controller. Initial relay ports were `127.0.0.1:60569` for SSH and `127.0.0.1:60570` for SMB. Those ports were temporary and are now closed. No installed decoy was restarted or reconfigured.

| ID | Check | Result and evidence |
| --- | --- | --- |
| G01 | Guest boot | PASS. Installed runtime started and reported both relay ports. |
| G02 | SSH negotiation | PASS. Real `SSH-2.0-OpenSSH_10.3` banner. |
| G03 | Incorrect password | PASS. Authentication rejected; no shell granted. |
| G04 | Correct synthetic login and persona | PASS. `buildbot`, UID/GID 501, `studio-mini`, macOS-shaped `sw_vers` 15.7.9 / 24G830, and FieldKit README. |
| G05 | Host filesystem and network containment | PASS within tested scope. A host-only canary was absent, only `lo` existed, route table was empty, root filesystem was memory-backed. |
| G06 | SFTP | PASS. README read plus byte-exact upload/download/delete. |
| G07 | SMB shares | PASS. Builds, Engineering, and Time Machine Backups each supported listing, writing, reading, renaming, and deleting a QA file. SMB and SFTP README bytes matched. |
| G08 | Concurrency | PASS. Three concurrent authenticated SSH sessions completed. |
| G09 | Real relay telemetry | PASS. Captured advertised-port event counts `{22: 9, 445: 1}`, source `127.0.0.1`. |
| G10 | Stop | PASS. Guest stopped and both relay listeners closed. |
| G11 | Restart and disposable data | PASS. Restart discarded a test marker and regenerated byte-identical persona content. |
| G12 | Cleanup | PASS. Final guest stopped; original sensor stayed running. |

SMB file operations reused a session. One TCP connection event is not expected to equal one SMB command or one file operation. These tests demonstrate real protocol behavior, not per-file forensic telemetry in the installed app.

The guest is a macOS-shaped persona, not a genuine macOS guest. The containment probe exposed Linux-style `/proc` and filesystem information. Passing the intended persona checks does not establish resistance to an adversary deliberately fingerprinting the operating system.

G05 is a bounded containment check, not a VM-escape audit. No exploit, resource-exhaustion attempt, or access to real host files was attempted.

## AI workbench and source-specific narrative

Installed Python modules served temporary loopback OpenAI-compatible, Ollama, and MCP endpoints against an in-memory database. These were not published by the installed sensor and did not generate native-app alerts.

| ID | Check | Result and evidence |
| --- | --- | --- |
| A01 | Model discovery | PASS. OpenAI/Ollama lists agreed on `fieldkit-coder:14b` and `release-notes:latest`; expected surface-specific headers present. |
| A02 | Non-streaming chat | PASS. Both APIs returned structured synthetic replies. |
| A03O | OpenAI streaming | FAIL. `stream: true` returned one `application/json` `chat.completion`, with no SSE records or terminal marker. |
| A03L | Ollama streaming | FAIL: fidelity. `stream: true` returned `application/json`, not declared NDJSON; one complete response had `done: true`. A tolerant client might consume it, but streaming fidelity was not met. |
| A04 | MCP discovery and all tools | PASS. Initialize, list tools, `list_projects`, `read_runbook`, `get_deployment`, and `search_secrets`; negotiated value 2025-06-18. Returned bait did not count as submitted credentials. |
| A05 | Synthetic key reuse | PASS. Reusing the exposed synthetic key emitted exactly one credential-used event. |
| A06 | Errors and recovery | PASS. Wrong-surface 404, malformed JSON 400, unknown-method -32601, unknown-tool `isError: true`; service continued responding. |
| A07 | Source campaign | PASS. Developer-agent intent, stage 3, and specific interaction `mcp.tools.call.read_runbook` recorded. |
| A08 | Cleanup | PASS. Temporary listeners closed; 19 connection events recorded in the retest. |

The streaming expectations were checked against primary documentation: OpenAI specifies SSE completion chunks, and Ollama describes streamed responses as newline-delimited JSON. [OpenAI streaming reference](https://developers.openai.com/api/reference/resources/chat/subresources/completions/streaming-events), [Ollama streaming reference](https://docs.ollama.com/api/streaming).

No external LLM was connected or manipulated. These checks establish deterministic protocol and narrative behavior, not proven effectiveness against an autonomous malicious agent. MCP transport conformance beyond the exercised JSON-RPC requests was not exhaustively tested.

### Corrected test expectations

The first A07 harness assertion expected the generic interaction label `mcp.tools.call`. The implementation correctly returned the more specific `mcp.tools.call.read_runbook`. The assertion was corrected and the AI round rerun. This was a **test expectation error**, not a product defect. The first combined streaming check was also split into separate OpenAI and Ollama results. Both streaming failures were reproduced with an explicit valid advertised model name. Use `results-ai-retest.json` as the authoritative AI result.

An initial health request to `/health` returned 404. The documented `/system/health` returned 200. The incorrect path was not counted as a product failure.

## Regression results

| Run | Source imported | Result |
| --- | --- | --- |
| Focused alert/AI/persona/protocol/bundle regressions | Installed sensor package | 56 passed, 3 failed, 0.99 seconds |
| Expanded decoy and lifecycle regressions | Installed sensor package | 408 passed, 3 deprecation warnings, 30.67 seconds |
| Three failing checks repeated on candidate | Candidate `sensor/src` | 3 passed, 0.09 seconds |

Installed total: **467 tests, 464 passed, 3 failed**. The separate candidate comparison is not included in that total.

The expanded set covered File Share, Home Assistant, Dev Server, mimic servers/templates/mDNS, identity, credentials, API routes, ordinary and deep orchestration, persona archives, and guest-runtime process-boundary behavior. These use disposable fixtures and mocked infrastructure where appropriate; a green orchestration test is not proof of live PF, ARP, Bonjour, or installed restart behavior.

Installed failures:

| Test | Observed failure |
| --- | --- |
| `TestDecoyTrip.test_publishes_alert_new` | Missing `connection_count` |
| `TestScanConnection.test_scan_burst_updates_one_unread_alert` | Missing `service_counts` |
| `TestScanConnection.test_repeated_same_endpoint_stays_one_connection_alert` | Missing `service_counts` |

The three warnings concerned deprecated websockets legacy integration, Uvicorn's websocket implementation, and Starlette TestClient's httpx integration. They did not fail the tests.

## Findings and follow-up order

1. **Acceptance blocker: the running installation is not the latest candidate.** Install the identified test package in an approved follow-up, then verify the installed file identity and alert-evidence tests again. The source comparison passes, but upgrade behavior is not tested here.
2. **Acceptance blocker: Studio Build Mac is absent.** Verify whether deep decoys are enabled and inspect startup diagnostics through approved administrator access. Do not assume this is an SSH daemon defect: the installed guest artifacts booted successfully in isolation. Configuration, startup, publication, and privileged-runtime causes remain unresolved.
3. **Coverage blocker: advertised-port LAN ingress is unverified.** After Studio appears, test its displayed IP from a second LAN machine. Verify routing, ARP/neighbor resolution, TCP 22/445, successful SSH/SFTP/SMB interaction, source attribution, and app evidence. Do not reuse `.203` without confirming its current assignment.
4. **Medium fidelity issue: AI streaming flags are ignored.** Non-streaming behavior passes, but streaming clients receive the wrong response framing. Any change must preserve the intended deception narrative and undergo deception review.
5. **Medium fidelity issue: invalid SSH-key bait.** The ordinary HTTP File Share serves an RSA-looking object that is not a usable key. This is distinct from the guest's real SSH authentication, which passed. A decision to make the bait parseable needs deception review, not generic hardening.
6. **Known realism limit: Linux guest internals remain observable.** The macOS-shaped shell identity is not full macOS emulation. This round did not score how readily an attacker would identify the facade.

## Untested or intentionally limited

- Live Studio guest creation, crash recovery, restart, and degraded-status UI under the installed sensor.
- External LAN advertised-port ingress, PF rule correctness, ARP replies, and remote source-IP preservation.
- Finder/Bonjour browsing, Time Machine backup-client acceptance, and guest SMB behavior from another operating system. The named backup share's file operations passed, not a complete backup.
- Exhaustive MCP transport negotiation, malformed-protocol fuzzing, large transfers, saturation, overnight soak, or VM-escape testing.
- Installer upgrade, reboot persistence, configuration migration, uninstallation, and Intel guest execution.
- Notification delivery outside the native app, such as external webhooks or email.
- Behavior of an actual adversarial LLM consuming the decoy narrative.

Private installed logs/database and live PF inspection required administrator access not available noninteractively. `sudo -n` reported that a password was required. Permissions were not weakened, private control credentials were not extracted, and this boundary was not bypassed.

## Side effects and final state

- Network Share retained 10 test connection rows and two synthetic credential-trip events, all from `192.168.1.18`.
- Four alerts from this round were visible in history: two High connection alerts and two Critical credential alerts. Two remained unread. Reviewing details marked two test alerts read; no existing history was cleared.
- Only disposable guest files were written, renamed, and deleted. The guest was stopped, destroying its memory-only filesystem. Small synthetic fixture files and QA scripts remain in `/private/tmp/squirrelops-functional-20260904` for reproduction.
- Temporary AI listeners and guest relays were closed. Final process inspection showed the original app, sensor, and helper PIDs unchanged and no test guest running.
- No existing decoy was disabled, renamed, removed, or restarted. No product source or configuration was changed. Results are local and uncommitted.

## Reproduction and saved evidence

Run tests only against owned decoys. The exact regression commands are saved in [regression-commands.md](/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/docs/testing/evidence/2026-09-04/regression-commands.md). Installed modules are deliberately selected using `PYTHONPATH`; the development virtualenv supplies the test runner and client libraries.

The custom harnesses are retained under `/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/build/test-artifacts/functional-20260904`. They currently target the temporary evidence directory and the verified endpoint from this session. Recheck ownership, PID, and endpoint before reusing them. The live credential phase intentionally creates native-app alerts.

| Evidence | Contents |
| --- | --- |
| [Environment](/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/docs/testing/evidence/2026-09-04/environment-results.json) | Installed identity, health, certificate enforcement, aliases, bounded Bonjour observations |
| [Native app observations](/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/docs/testing/evidence/2026-09-04/ui-observations.json) | Counters, alerts, history, credential badges, final process state |
| [Owned-listener probes](/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/docs/testing/evidence/2026-09-04/running-sensor-probes.json) | Each of the 26 local endpoint outcomes |
| [Guest and initial AI run](/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/docs/testing/evidence/2026-09-04/results.json) | G01-G12 plus original AI results; A07 assertion was subsequently corrected |
| [Authoritative AI retest](/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/docs/testing/evidence/2026-09-04/results-ai-retest.json) | Separate streaming failures and corrected campaign check |
| [Live share browse](/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/docs/testing/evidence/2026-09-04/live-share-browse.json) | Directory, password file, invalid key, and 404 checks |
| [Live credential reuse](/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/docs/testing/evidence/2026-09-04/live-share-credentials.json) | Synthetic credential submission results, no credential values |
| [Focused installed regressions](/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/docs/testing/evidence/2026-09-04/installed-regressions.xml) | 56 passing and three failing test cases |
| [Expanded installed regressions](/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/docs/testing/evidence/2026-09-04/installed-expanded-regressions.xml) | All 408 additional test cases |
| [Candidate comparison](/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/docs/testing/evidence/2026-09-04/candidate-alert-regressions.xml) | Three candidate-source checks passing |

No production credentials, private control keys, or full planted key bytes are included. Saved JSON contains synthetic persona names and local test addresses.
