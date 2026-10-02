# SMB delay: build-time DNS configuration leaked into the guest

Update: the user approved the correction. The subsequent
[implementation and local runtime comparison](2026-10-01-guest-resolver-fix.md)
confirmed the measured stall and rebuilt a local-test installer. The analysis
below preserves the evidence and uncertainty at the time of diagnosis.

## Outcome

Read-only inspection confirmed a guest packaging defect: the exact image
installed on the Mini includes Docker/BuildKit hostname and resolver settings.
Its runtime hostname is missing from `/etc/hosts`. Upstream code paths closely
match the two roughly ten-second pauses in the successful anonymous SMB
diagnostic, but **causation is not yet runtime-proven**.

The [SMB diagnostic and cleanup](2026-10-01-mini-smb-diagnostic-result.md)
are complete. No product source, installed files, service state, firewall rules
or databases were changed during this investigation. No new probes were sent.
The isolated source-research browser session was closed after inspection.

## Exact artifact evidence

The local `guest/studio-mini/build/arm64/studio-mini.initramfs` and Mini's
`/Applications/SquirrelOps Home.app/Contents/Resources/DeceptionGuest/studio-mini.initramfs`
have the same SHA-256:

`7b908f98c92c580622fb260f33facc4ee22e88c281d8802db561af4edd52948d`

Both guest manifests have SHA-256:

`a8bf96c81c1eb25b63a6a9316044032b4842457ff472b0199da5aeb22ed77b2b`

This is the guest shipped in the already pinned diagnostic installer, SHA-256
`3d18ebac2fae343fd9c710ad2a187ec3f4bf6e4fd9cfda3bc3654214db7c67ea`.
Archive contents were read with `/usr/bin/tar -xOf`; no guest startup or archive
extraction to a runtime directory was needed.

| Packaged file | Observed content |
| --- | --- |
| `/etc/hosts` | `127.0.0.1 localhost buildkitsandbox`; `::1 localhost ip6-localhost ip6-loopback` |
| `/etc/resolv.conf` | `nameserver 192.168.65.7` |
| `/etc/hostname` | `localhost` |
| `/etc/nsswitch.conf` | `hosts: files dns`, plus a comment noting musl does not implement NSS |

The NSS file is recorded as an artifact, not evidence that musl follows its
policy. The relevant resolver implementation is musl itself.

The package inventory pins Samba `4.23.8-r0` and musl `1.2.6-r2`.

## Local source path

- `guest/studio-mini/Dockerfile` archives the build container's root with
  `find` and `cpio`. It excludes build output, device, proc and sys contents,
  but does not exclude or replace the build-injected hosts/resolver files.
- `sensor/src/squirrelops_home_sensor/decoys/deep/persona.py` supplies
  `/etc/hostname` as `studio-mini` for the `studio-mini.local` persona.
- `guest/studio-mini/rootfs/sbin/init` validates that persona and sets the
  running hostname to `studio-mini`. It does not repair hosts or resolver data.
- `app/Sources/SquirrelOpsDeceptionGuest/GuestManifest.swift` configures zero
  network devices. The guest initializes loopback and uses VSOCK relays.
  The packaged Docker DNS address is consequently unreachable through a guest
  network adapter. Enabling DNS egress is not an acceptable remedy.
- `scripts/verify-guest-bundle.py` verifies declared containment, hashes and
  architecture but does not reject these contents inside the initramfs.
  Existing supply-chain tests do not cover this build-environment leak.

These are confirmed artifact/source defects, independent of the timing theory.

## Why the timing matches

Samba's authentication setup requests both its full DNS name and its DNS
domain. The domain helper calls the full-name helper again. Successful
full-name resolution is cached, but failure returns without populating that
cache. Sources: [authentication setup](https://raw.githubusercontent.com/samba-team/samba/samba-4.23.8/source3/auth/auth_generic.c),
[domain helper](https://raw.githubusercontent.com/samba-team/samba/samba-4.23.8/source3/lib/util.c),
and [full-name lookup/cache](https://raw.githubusercontent.com/samba-team/samba/samba-4.23.8/source3/lib/util_sock.c).

Both SMB2 negotiation and session setup invoke that authentication setup.
Sources: [negotiation](https://raw.githubusercontent.com/samba-team/samba/samba-4.23.8/source3/smbd/smb2_negprot.c)
and [session setup](https://raw.githubusercontent.com/samba-team/samba/samba-4.23.8/source3/smbd/smb2_sesssetup.c).

musl 1.2.6 defaults to a five-second DNS timeout and two attempts. The retry
interval divides that timeout by the attempt count; the overall polling loop
uses the five-second budget, not ten seconds per lookup. Failed sends do not
immediately terminate that polling loop. Sources: [resolver defaults](https://git.musl-libc.org/cgit/musl/tree/src/network/resolvconf.c?h=v1.2.6)
and [send/retry/poll loop](https://git.musl-libc.org/cgit/musl/tree/src/network/res_msend.c?h=v1.2.6).

**Inference:** if own-hostname resolution takes the timeout path twice per
authentication setup, negotiation and session setup can each consume about
ten seconds. That closely fits the guest's 10.450-second first-response delay
and client output arriving around 10.266 and 20.397 seconds, with successful
listing at 20.838 seconds. The observed total was 20.841 seconds.

No guest syscall trace or controlled artifact comparison was collected.
Upstream tags match packaged base versions, but this investigation did not
independently audit Alpine's downstream patch set. Therefore this is a strong
source-backed explanation, not proof that every millisecond or every earlier
failed test had this cause. Little Snitch policy was not inspected or changed;
the question about new prompts in this diagnostic remains unanswered.

## Proposed correction, not yet authorized or implemented

1. Package deterministic persona-consistent hosts and resolver files, outside
   Docker's injected-file mounts. Ensure the short hostname and `.local` name
   resolve locally, and no builder hostname, nameserver or search domain leaks
   into the archive. Keep the guest without a network adapter or external DNS.
2. Add regressions that inspect actual packaged contents, reject seeded builder
   configuration, verify persona consistency and preserve containment. Hash
   validation alone cannot establish semantic correctness.
3. Run a controlled local before/after comparison with the same SMB client,
   explicit null session and timeout, fresh guests and unchanged filter policy.
   Measure first response and total listing time, and compare protocol identity,
   shares, synthetic authentication, SSH behavior and containment.
4. Only after that comparison passes, rebuild and verify a new local installer.
   Installation on the Mini, additional LAN acceptance, commits, pushes and
   publication remain separate actions, not implied by this proposal.

This needs a deception review: successful hostname resolution can change SMB
DNS identity fields as well as response timing, and these files are visible
inside a logged-in guest. Aligning them with the established persona must not
change the intentional authentication behavior, shares, banners or simulated
weaknesses. Do not substitute larger acceptance timeouts, authentication
hardening, network-device enablement or broader firewall allowances for this
correction.

The engineering-constraints skill kept the confirmed artifact defect separate
from the runtime hypothesis and left implementation behind the approval boundary.
