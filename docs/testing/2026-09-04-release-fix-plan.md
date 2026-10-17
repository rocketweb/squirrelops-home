# 2.1 release fixes after local functional testing

## Scope and plan

Matt requested a plan followed by implementation of the findings in the September 4 functional report. Work stays in the existing 2.1 candidate checkout. Preserve the original report and evidence.

1. Add failing protocol and live-HTTP regressions for OpenAI SSE and Ollama NDJSON, including Ollama's streaming default and explicit non-streaming behavior. Implement framing without changing the synthetic narrative, banners, authentication, or existing errors.
2. Add a real RSA parser/signature round-trip test for generated SSH bait. Generate independent unencrypted RSA PEM keys, never authorized against the host. Repair ordinary file-share credential loading on upgrade so invalid legacy bait is replaced for serving, while retaining original credential rows and trip history.
3. Reproduce missing-host lifecycle and visibility gaps in isolated tests. Add operator-facing startup diagnostics and safe retry behavior for an enabled but unavailable Studio host, without bypassing IP verification, artifact validation, quarantine, or intentional stop state. Do not claim this establishes the private installed startup cause.
4. Rerun focused and broad sensor tests, Swift tests for any UI/model change, live guest acceptance, and local build checks. Produce a uniquely named local-test installer, checksum, and follow-up results.
5. Keep installation, privileged runtime diagnosis, second-machine LAN acceptance, signing/notarization for publication, commit, push, and release as separate states requiring the applicable approval.

## Deception review before implementation

These are intentional fidelity repairs requested after the functional report, not generic decoy hardening. The review stops automatic application of security recommendations and explicitly scopes the byte-visible changes below.

| Surface | Intentional change | Invariants and tests |
| --- | --- | --- |
| OpenAI/Ollama chat | Correct stream framing and terminal records; Ollama streams by default | Same persona content, deterministic bounded response, no outbound model call; explicit non-streaming bytes and existing error snapshots preserved |
| SSH-key bait | Parseable RSA PEM instead of random bytes in RSA delimiters | Same filename and PEM family, unencrypted synthetic material only; no authorization on the Mac or any real service; historical rows retained |
| Studio lifecycle/control UI | Explain unavailable state and retry eligible startup failures | No new decoy privilege or egress; no direct-backend bypass; intentionally stopped hosts stay stopped |

Streaming changes response framing and write sequencing intentionally. No artificial delay, rate limit, lockout, security header, stricter decoy authentication, TLS modernization, or banner removal is authorized or planned. Tests must cover byte-visible framing and unaffected responses before and after the change. Full independent cross-device deception review remains a release gate.

## Explicit limits

- The running installation's private config and logs are not readable by the current account; `sudo -n` still requires a password. Its exact Studio startup failure is unverified.
- Same-host backend timeouts do not justify changing PF rules. Second-machine advertised-port acceptance remains necessary.
- The Linux-backed macOS-shaped guest is the approved 2.1 architecture. Replacing it with full macOS virtualization or attempting comprehensive Linux fingerprint concealment is not a small bug fix. Document this limit honestly; do not weaken containment or claim full macOS emulation.
- The three alert-evidence regressions already pass against the candidate. Package the existing fix with this work; do not duplicate or redesign it.

## Completion evidence

Record the observed failing tests, passing reruns, exact package checksum, source diff, and outstanding installed/LAN checks in a separate follow-up report. Do not rewrite the original failing results.

## Execution status

- Completed steps 1 and 2: streaming and RSA bait regressions reproduced first, then fixed and verified, including legacy-history preservation.
- Completed the locally reproducible portion of step 3: idempotent startup, bounded retry, degraded-host stop, authenticated diagnostics, and an empty-inventory UI notice. The original installed startup cause remains unverified.
- Completed step 4: 2,202 sensor tests passed, 468 Swift tests passed, live guest acceptance passed, and 176 regressions passed against the extracted installer payload. A new arm64 local-test installer is ready.
- Step 5 remains an explicit boundary. Nothing was installed, committed, pushed, or published. Installed and second-machine LAN acceptance are still required.

See [implementation and verification results](2026-09-04-release-fix-results.md) for the artifact, checksum, evidence, and remaining gates.
