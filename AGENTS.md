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

## Open testing items

- `decoys/types/mimic.py` narrowed `except Exception` to three specific types in connection-cleanup
  paths. Inject an unexpected exception type into each path and assert the socket still closes the
  way the imitated service closes.
- Add a regression guard asserting decoy credential generation uses a CSPRNG, so a future refactor
  cannot quietly revert to `random`.
- Add byte-exact snapshot tests for decoy responses so any attacker-visible change fails CI and
  requires explicit review.
