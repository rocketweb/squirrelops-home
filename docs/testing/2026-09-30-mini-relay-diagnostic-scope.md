# Mini diagnostic upgrade and bounded protocol acceptance

Status: prepared for attended approval, not executed. This scope covers one
candidate, one Mini boot and one laptop test attempt. It does not authorize
release publication or changes to Little Snitch.

## Exact target and artifact

- Mini: `matt@100.108.203.27`, ARM64, macOS build `26A434`, boot seconds
  `1790777754`. en0 `192.168.1.115`, en1 `192.168.1.254`.
- Candidate: `SquirrelOpsHome-2.1.0-relay-diagnostics-20260930-local-test.pkg`.
- SHA-256: `3d18ebac2fae343fd9c710ad2a187ec3f4bf6e4fd9cfda3bc3654214db7c67ea`.
- Size: 136,565,301 bytes. Unsigned installer, ad-hoc payloads, not notarized.
- Current installation: launchd-budget candidate, sensor receipt install time
  `1790784842`. Executables are checked against the pinned installed hashes.
- Client: laptop `192.168.1.7`, route through `wlp0s20f3`.
- Decoy target: `192.168.1.240` only. No `.241`, Studio, or native Mini service
  probes. The existing configuration already selects only `.240` and is not edited.

## Baseline and backup

Require both product jobs unloaded and explicitly disabled, no product runtime,
no owned alias, no published proxy ARP, native listener/UID parity, unchanged
configuration, and the seven saved decoy identity/status rows below.

| ID | Type | Address | Port | Saved intent |
| --- | --- | --- | --- | --- |
| 1 | deep | 192.168.1.240 | 445 | active |
| 2 | deep | 192.168.1.240 | 22 | active |
| 3 | deep | 192.168.1.240 | 11434 | active |
| 4 | deep | 192.168.1.240 | 1234 | active |
| 5 | deep | 192.168.1.240 | 8765 | active |
| 6 | dev_server | 192.168.1.115 | 60556 | active |
| 7 | home_assistant | 192.168.1.115 | 51232 | active |

Read configuration and database metadata without changing permissions. Read
SQLite as UID/GID 309 with no supplementary groups and a read-only connection.
Create verified root-private backups of the current app, sensor, helper,
launch plists, receipts, owned runtime state and a consistent SQLite snapshot.
Retain them under `/Library/SquirrelOps/acceptance-backups/mini-relay-20260930.*`.

Require PF disabled with zero states and an empty reviewed anchor tree. Inventory
concrete child anchors, not the broken recursive wildcard on this OS. Abort on
unreviewed policy, baseline drift or an existing candidate attempt claim.

The runner creates private evidence before confirmation, but performs no package,
configuration, SQL, service or PF mutation before the operator types:

```text
INSTALL DIAGNOSTICS AND TEST 240
```

## Approved work if confirmed

1. Check `.240` for ARP conflicts. Claim this candidate attempt once. Acquire
   and privately record one owned PF enable reference. Enable only
   `com.squirrelops.sensor` and `com.squirrelops.helper`, create the temporary
   explicit local-test installer opt-in and install the pinned package.
2. Verify installed hashes, signatures, unchanged configuration, sensor health,
   the 60-second launchd shutdown allowance, all five guarded `.240` mappings,
   and restoration of both saved classic listeners. The app stays closed.
3. Perform one ordinary sensor stop/start. Require guest exit, withdrawn alias,
   cleared ownership and empty product policy before starting again. Confirm
   health/publication and saved intent after restart.
4. Permit one laptop run while readiness is current and at least ten minutes
   remain. First test SSH banner, SMB share discovery and three synthetic AI
   endpoints. If any fails, skip all authentication and file operations.
5. Only after those protocols pass, test denial of the five private backend
   ports and port 5900 on `.240`, never on the Mini's real address. Failure
   stops further client work. Then test one wrong password per protocol, the
   synthetic buildbot login/persona, and one uniquely named upload/read/delete
   round trip over each of SFTP and SMB. Use only the generated decoy login;
   do not print it or expose it in process arguments. No brute force or exploit.
6. Observe for at most 20 minutes after readiness, or until the operator presses
   Return. Stop services/guest, withdraw owned networking, restore both disabled
   jobs, verify native services and policy parity, then release only this run's
   PF reference. Never use a global flush, reset, force-kill or disable command.

Starting the installed sensor also resumes its existing discovery and automatic
classic-decoy deployment. This runner does not disable or reconfigure those
features. The original seven rows must remain unchanged. Additional classic
host-listener rows on `.115` and high ports are preserved and reported, not
deleted and not mistaken for corruption. Unexpected virtual-host additions or
changes to saved identity/intent stop the test for review.

## Evidence and failure behavior

Capture packet metadata, not payload dumps, only for `.7` with `.240` on en0/en1.
Retain root-only command evidence, service-account TCP queue/state metadata and
PF state metadata. Publish only fixed-vocabulary relay checkpoints, numeric
socket queues for UID 309 at `.240` with peer `.7`, counters and status. Raw log
text, nonce markers, credentials and PF reference tokens are not public output.
Checkpoint export reads an 8 MiB log tail, at most 1,539 records; rotated history
is excluded and missing records are not a firewall verdict.

The generated synthetic guest login is exported separately as a private file
owned by the operator, mode 0600, for transfer to fresh root-private laptop
staging. It is not a production credential or part of the public report. The
client requires exact package/scope/boot/configuration pins, fresh readiness,
five exact mappings and a never-used results file.

Leave new Little Snitch/macOS prompts unanswered and report them. No existing
rules are removed or broadened. The new ad-hoc executable identity may prompt.

On failure, retain installation/data/backups and stop when safe. A surviving
guest, uncertain installer, changed policy or failed hold restoration retains
protection and requires review. No automatic database restore or downgrade.
The ordinary inverse is verified shutdown and restoration of the disabled hold.
Restoring old application/data bytes is a separate attended operation against
the verified backup, with fresh approval and no newer writes overwritten.

## Boundaries still open afterward

Even a successful run does not complete the separate A5 live listener/state
replacement and older-rule migration cases, final Developer ID signing and
notarization, signed-artifact acceptance, independent review, or publication.
Those are separate release phases. No commit, push, merge, tag, release,
website or Homebrew update is included in this scope.
