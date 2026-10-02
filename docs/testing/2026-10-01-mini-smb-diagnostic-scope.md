# One SMB-only diagnostic window

Matt approved this scope with "keep going" after the completed filter retest:
one SMB-only diagnostic window on the same installed Mini build, with no
installer, firewall changes or file writes. He subsequently confirmed the
narrow incoming guest rule from laptop `192.168.1.7` is still active. This is
operator-reported, not a rule audit or approval to renew/broaden it.

## Baseline and startup

Mini `100.108.203.27`, boot `1790777754`, ARM64 macOS build `26A434`.
Package SHA-256:
`3d18ebac2fae343fd9c710ad2a187ec3f4bf6e4fd9cfda3bc3654214db7c67ea`.
Retain the same seven saved decoys and `.240`-only configuration. Both apps
stay closed. No Studio restart, `.241` test, SQL recovery, global PF policy
edit, Little Snitch change or installer operation.

Resolve the prior durable backup only through the exact root-private claim
`protocol-filter-approved-1790777754-3d18ebac2fae-attempt.json`. Require its
cleanup receipt SHA-256
`23e496726d24f1e81acce52328128dfdac963d567772b8cef613c203e943ce6c`.
Recheck stopped/disabled jobs, absent guest and aliases, empty disabled PF,
installed payload/receipt parity, unchanged config, saved identities and native
listeners. Preserve verified private installation/config backups and a
consistent SQLite snapshot. Keep the `.240` ARP conflict check enabled.

Use the new exclusive claim `protocol-smb-diagnostic-1790777754-3d18ebac2fae-attempt.json`.
Reuse the tested start-only and cleanup implementations. Acquire one privately
retained PF reference, restore only the two product disabled overrides and
bootstrap helper then sensor. No repeat restart test. The unchanged package is
used only for a private pinned Python extraction, not installation.

## One laptop client

Require fresh readiness at most 30 seconds old, ten minutes remaining, matching
diagnostic scope/package/boot/UID/configuration and five exact mappings. Verify
laptop source `.7` through `wlp0s20f3`. Transfer endpoint and status files only.
Do not transfer/read the synthetic login for this attempt.

Run one `smbclient` invocation to `.240:445`, maximum **45 seconds**, per-operation
timeout five seconds, debug level three. Use explicit anonymous identity
`-U % -N`, empty client configuration and Kerberos off so no real credentials
or caches are used. Pin both destination IP and port; do not fall back to 139.
No SSH, AI API, containment probe, password attempt or file operation follows.

This is a diagnostic variant, not an identical acceptance rerun: the earlier
client used default configuration/username and a 20-second parent deadline.
A result after 20 seconds does not by itself pass the earlier acceptance gate.
Record monotonic timing, fixed-vocabulary SMB milestones, exit/deadline status
and returned known share names. Bound raw debug data to 256 KiB, retain it only
in the root-private laptop directory and do not print arbitrary server output.
Never automatically repeat a failed/partial invocation or remove its claim.

The Mini records the same scoped relay checkpoints, counters, socket metadata
and packet headers. Existing discovery and classic auto-deployment may run;
retain/report additional `.115` host listeners. Stop on virtual-host drift.
New filter prompts remain unanswered and are reported, not worked around.

## Cleanup

Return after the client triggers guarded teardown; the outer window also ends
at 20 minutes. Stop guest/services, withdraw owned aliases, restore disabled
jobs, and release only this run's PF reference. Uncertain teardown retains
protection/evidence. No force-kill of product processes or PF reset. Preserve
installation, data, configuration, native services and all evidence.

Attended confirmation: `START ONE SMB DIAGNOSTIC`.
No source fix, commit, push, signing, notarization or public release is implied.
