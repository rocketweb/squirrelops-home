# AI connection setup for Home 2.1

Date: 2026-09-28. Local changes were built on `0c9ce02` in
`feature/deception-depth-2.1.0-current`. The source publication branch is
`feature/ai-setup-2.1`, based on the file-identical merged main `6db225c`.

## Delivered in source

- Explicit model discovery from the sensor's saved AI configuration, with a
  searchable native model chooser and manual model-ID entry.
- Explicit synthetic classification and naming tests using production prompts
  and parsers. Discovery does not mark a model validated.
- Saved provider keys remain on the sensor. Cloud origins remain canonical;
  redirects and environment proxies are disabled. No provider error bodies or
  raw exception strings are returned to the app.
- Authenticated, no-store management endpoints, a single in-flight diagnostic,
  six starts per minute, a 50-second total deadline, 2 MiB response limit,
  1,000-model limit, and bounded Fireworks pagination. Test generation is capped
  at 512 output tokens per request, with at most two requests.
- Configuration edits invalidate earlier results. The app waits for its
  current save and does not test after a failed save. The sensor rejects results
  when another client changes the saved configuration during a request.
- Model discovery has no side effects on the model selection. Empty or
  unsupported catalogs retain manual entry and an explicit generation test.
- Updated user guide, AI feature guide, development guide, security model,
  release notes, and credential-filename help.

No new dependency, installer change, privileged operation, or attacker-visible
decoy change was needed. The existing classifier accepts an injected HTTP
client so diagnostics can bound transport and output while reusing its prompts
and parsers. Its normal runtime client defaults are unchanged.

## Verification

| Check | Result |
| --- | --- |
| Initial sensor tests before implementation | 16 failed: missing module/routes |
| Initial app tests before implementation | Compilation failed on missing diagnostic types/endpoints after resolving compiler-cache access |
| Empty `choices` regression | Observed `IndexError`, then fixed to report an incompatible response |
| Config response caching regression | Observed missing header, then added `Cache-Control: no-store` |
| Final full sensor suite | 2,349 passed, 1 skipped, 86.62 seconds |
| Focused AI diagnostics | 28 passed, including a real disposable loopback HTTP server |
| Full macOS app suite | 400 tests in 38 suites passed, 14.769 seconds |
| macOS compilation | Passed using CLT and macOS 26.5 SDK, documented scratch path |
| Lint | `ruff check .` passed |
| Patch hygiene | `git diff --check` passed |
| Native AI controls | Rendered at 320, 560, and 760 points in light and dark mode; narrow light and standard dark images visually inspected |
| Public OpenRouter catalog | Real read-only discovery parsed 460 models; no key sent, no generation calls |

The provider fixtures cover duplicate/non-text models, malformed and oversized
data, missing provider/key, canonical cloud origins, unsupported discovery,
HTTP 401/402/403/404/429/500, redirects, timeout, cancellation, partial test
success, stale configuration, overlapping probes, and bounded pagination.

The disposable loopback test exercises the real HTTP client and production
parsers through one model-list GET and two generation POSTs. It closes its
temporary server and does not contact an installed AI service.

The one full-suite skip is the opt-in live deep-decoy guest test, whose runtime
environment was not enabled for this change. Existing upstream deprecation
warnings and CLT linker search-path warnings remain. This work does not close
the separate release PF, signed-package, or guest-containment gates.

### Reproduction

From the sensor directory:

```sh
.venv/bin/pytest tests/ -q --tb=short
.venv/bin/pytest tests/integration/test_ai_diagnostics.py -q --tb=short
.venv/bin/ruff check .
```

Build app tests with the CLT/macOS 26.5 command in `docs/DEVELOPMENT.md` and run
the compiled `SquirrelOpsHomeTests` executable with `swiftpm-testing-helper`,
the documented CLT dynamic-library paths, and `--testing-library swift-testing`.
Set `SQUIRRELOPS_AI_UI_OUTPUT` to an absolute directory to save the six renders.

Local logs and images are retained under `build/test-artifacts/`:
`ai-swift-red.log`, `ai-swift-build.log`, `ai-swift-tests.log`,
`ai-sensor-full.log`, `ai-diagnostics-final.log`, and `ai-ui/`.

## Credential filename finding

`credential_filename` is passed to the ordinary decoy orchestrator at sensor
startup. New `file_share` decoys persist it as `password_filename` and serve
the planted credential file over HTTP. Existing decoys keep their persisted
filename. A settings edit is not a live rename.

The Studio Build Mac guest uses a separate persona archive. Its real SMB and
SSH files include synthetic project `.env.local` credentials, but do not read
this setting. The app and user-guide wording now state that distinction.
Neither the HTTP filename behavior nor the guest files were changed.

## Remaining acceptance and delivery state

Local implementation and the checks above are complete. Real authenticated
LM Studio, Ollama, Fireworks, and paid OpenRouter generation were not exercised.
Their documented catalog formats and failures were tested with fixtures. The
public OpenRouter catalog proves current discovery parsing, not paid model
permission or generation compatibility. A single successful synthetic test is
not an assessment of ongoing model quality or availability.

After reviewing the installed build, Matt reported "this works well" and
authorized source commit and publication. This records user acceptance of the
local AI setup flow, not provider-by-provider certification or a separate
foreground keyboard and spoken VoiceOver acceptance record for the new chooser.

The changes were packaged and installed locally at the operator's request, as
recorded below. The review package predates source publication; its checksum
identifies the installed bytes. GitHub records the subsequent commit and PR
state. No signed public release is claimed. Earlier untracked LAN acceptance
notes and evidence were preserved separately from this source publication.

## Local review package and installation

Built on 2026-09-28 from the same uncommitted AI changes on `0c9ce02`, using
the documented CLT/macOS 26.5 SDK and `.build/ai-setup-release` scratch path.
This is an ARM64 local-test package: app and native payload signatures are
ad hoc, and the installer is unsigned and not notarized. It is not a public
release artifact.

Artifact under `build/test-artifacts/`:

`SquirrelOpsHome-2.1.0-ai-setup-20260928-local-test.pkg`

SHA-256:

```text
3e8c0fc78befad3365fdbff5583d9f85c6b6fe01816b5863edbebeceaa4b8f5f
```

| Check | Result |
| --- | --- |
| Release-mode package build | Passed; previous installer retained separately |
| Locked standalone Python dependencies | 39 distributions verified; no broken requirements |
| Sensor native binary signing | All 48 binaries signed and verified |
| Extracted app signature | `codesign --verify --deep --strict` passed |
| Guest resource manifest and hashes | `verify-guest-bundle.py --architecture arm64` passed |
| Extracted first-party sensor payload | Matched source recursively, excluding bytecode caches |
| Packaged Python smoke test | Imported both `/config/ai/models` and `/config/ai/test` |
| Focused AI recheck and lint | 28 tests passed in 1.17 seconds; Ruff passed |
| Installer completion | Succeeded at 15:59:58 EDT; approximately 60 seconds |
| Installed payload parity | App, helper, guest runtime hashes and both first-party Python package trees matched the extracted candidate |
| Sensor recovery | Two consecutive healthy API responses; launchd process remained running |
| Decoy recovery | All 32 prior active IDs, bind addresses and ports matched; 1,249 stopped decoys remained stopped |
| Data preservation | Baseline device, decoy, alert, planted-credential and pairing IDs retained; configuration file byte-identical |
| Database checks | Quiescent rollback integrity check and live database quick check passed |
| App reconnection | Automatic local enrollment completed; Settings loaded with app and sensor version 2.1.0 |
| Installed AI controls | Settings exposed the new model-entry, discovery, chooser and test controls, with saved Custom OpenAI-compatible provider preserved |
| Live authentication boundary | Both new POST endpoints returned HTTP 403 without a client certificate; no provider request was made |

The first focused recheck ran within the filesystem/network sandbox and failed
only when binding its disposable loopback test server (`EPERM`). The permitted
rerun passed all 28 tests. No test was removed or weakened.

The first maintenance preflight stopped before changing files because it
expected the earlier 30-decoy baseline. A current read found 32 active decoys.
The maintenance script was adjusted to capture and compare the current exact
active set, rather than relying on an earlier fixed count. The final upgrade
passed that comparison. This was a maintenance-script correction, not a
product-code or decoy-configuration change.

Sensor startup took roughly six minutes, including persisted decoy recovery,
before the API and app became available. The new local-test credential
namespace used normal automatic enrollment. No AI provider settings were
edited and no authenticated provider discovery or generation was invoked for
installation acceptance. The user can now review those controls in Settings.

The private rollback directory is:

`/Library/SquirrelOps/acceptance-backups/ai-20260928.APRK9lXJ`

It retains the previous app, helper, sensor runtime, configuration, receipts,
data and consistent SQLite snapshots, checksums, installer log and scoped
recovery instructions. Keep this root-only directory private: it contains
credentials. `INSTALL-VERIFIED` records completion of the maintenance checks.
No rollback was needed.

Build and focused-test logs are `ai-package-build-20260928.log` and
`ai-diagnostics-package-check.log` under `build/test-artifacts/`. The installer
and matching `.sha256` file are retained there for local review. PackageKit
emitted `write: Permission denied` diagnostics during bundle analysis, but
successfully produced the package; its extracted metadata explicitly had
`relocatable="false"`, and the verified installation targeted `/Applications`.
Expected local-test Gatekeeper rejection is not a notarization success claim.

The remaining provider, foreground accessibility, PF and release-signing
acceptance limits above are unchanged by this local installation.

## Source publication preflight

Before the approved commit and source publication, the current tree was checked
again: 2,349 sensor tests passed with the same one opt-in live-guest skip;
400 app tests in 38 suites passed after a fresh build; Ruff passed; Pyright
reported zero errors and 29 warnings; and `git diff --check` passed. The existing
CLT linker and upstream deprecation warnings remain. Logs use the
`ai-publish-` prefix under ignored `build/test-artifacts/`.

The current GitHub release environment requires independent approval from
`chrissyrocket`. PR #49 is merged, but its approval predates these AI changes.
This follow-up therefore uses a new PR against merged main. The public Home
release still requires the [A5 live PF acceptance gate](2026-09-26-pf-safety-development.md#live-acceptance-gate-not-executed)
and the protected signing/publication workflow. Local acceptance and source
publication do not waive those requirements or authorize publishing the
unsigned review installer as a release asset.
