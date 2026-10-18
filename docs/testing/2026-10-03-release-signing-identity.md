# Home 2.1 release signing identity

Date: October 3, 2026. This is a signing-identity correction and documentation
follow-up. It does not change product code, the accepted source, or published
tags. The protected release workflow has been dispatched, but no installer
artifact or Home 2.1 release has been published at this checkpoint.

## Accepted source

- Source: `300569ba15c375a77201cccfe7c27dc2d0da888e`, merged PR #53.
- The merged tree matches tested head `c8bb4d89e9abbc4588047c1934621717458daa43`.
- Post-merge Sensor CI `37094369192`, App CI `37094369150`, and Supply Chain CI
  `37094369163` passed on that source.
- [Chrissy's explicit acceptance](https://github.com/rocketweb/squirrelops-home/pull/53#issuecomment-5965316470)
  covers the documented A5 test limitations for this exact source and permits
  the signed installer build. Those gaps remain limitations, not passed tests.
  Publication still requires acceptance of the exact signed/notarized installer.

## Failure and correction

The three tags have valid local GPG signatures but GitHub reported `bad_email`.
Their tagger uses the required repository identity,
`Matt MacDougall <matt.macdougall@rocketweb.com>`. The selected key and its
registered public copy contained only `Matt MacDougall <mattmac@gmail.com>`.
That mismatch should have been caught before the tags were pushed.

Matt authorized adding the Rocket Web identity and updating the documentation
and public-key registration. The original public-key export and GitHub's public
record were backed up first. The local key now retains the Gmail identity and
includes the Rocket Web identity. No private key was exported or uploaded.

The primary fingerprint remains
`DF61289018C7BB668E777C94DFCEDCF01DD4FDFE`. All three unchanged tags pass
`git verify-tag` after the local identity addition.

| Tag | Original and retained tag-object ID |
| --- | --- |
| `app-v2.1.0` | `0163216b45862412186ef11bbfff2fea7769221b` |
| `sensor-v2.1.0` | `5aec873bf5d0a05938f242c857701c1a155f294f` |
| `home-v2.1.0` | `e7084adb15a15b63082d3fe2b4ffa20596b9c36f` |

All three target the accepted source above. The sensor tag identifies the
component in the macOS package only; Linux publication remains blocked.

## GitHub registration and verification

GitHub Settings confirms the Rocket Web address is already verified. After the
account owner's access confirmation, GitHub rejected the updated public export
because subkey `C57737336CD07F7C` already exists in the original registration.
That is the expected unchanged subkey, not a new key conflict.

Matt explicitly confirmed replacement of only the original GPG registration
`5215101`, titled `Matt MacDougall Release Signing`. It was removed and the
verified updated public export was registered as `5370427`. GitHub's public
key API now reports both email addresses as verified. The original and updated
public material are retained. SSH keys, private key material and release tags
are unchanged. The CLI's permissions were not expanded.

GitHub's tag-object API now reports `verified=true` and `reason=valid` for all
three existing tags, with the exact object IDs and target recorded above.

## Remaining steps

Protected main was rechecked at the accepted source before dispatching
[release run 37096783884](https://github.com/rocketweb/squirrelops-home/actions/runs/37096783884).
Chrissy independently approved `Verify protected Home release inputs`, which
passed. The next job, `Build pinned Studio Mini guest bundles`, failed because
11 Alpine package versions differed from the reviewed inventory. The ARM64
inventory comparison failed before the x86_64 build ran. Signing and publication
were skipped; the run produced no artifacts or release draft.

This is a separate guest dependency/build blocker, not a remaining signing-key
failure. A reviewed recovery and fresh release run are required; do not rerun
the failed workflow, bypass the inventory check or move published tags.
Acceptance of the exact signed and notarized package still precedes publication;
the earlier local test package does not satisfy that gate.

These documentation edits are separate from the already-tagged source. Do not
advance protected main before the pending release's exact-main input check.

## Documentation verification

- `git diff --check`: passed.
- Every Bash example in `docs/RELEASE_SECURITY.md` and `docs/DEVELOPMENT.md`
  parses with `bash -n`.
- `sensor/tests/unit/test_supply_chain_security.py`: 47 passed in 4.40 seconds,
  using this checkout's source explicitly on `PYTHONPATH`.
- GitHub's ref and tag-object APIs confirm protected main and all three tag
  objects still match the IDs recorded above. The documented read-only remote
  verification example also passed against all three tags.

These are focused documentation and release-control checks, not a repeat of
the full application or live-network acceptance suites.
