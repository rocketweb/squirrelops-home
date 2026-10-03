# Disposable macOS upgrade test: host preflight

Date: October 2, 2026. Status: **superseded; VM not created**.

Matt subsequently authorized removing the Mini's existing SquirrelOps
installation and data, installing official 2.0.3, and testing an in-place
upgrade. Continue with the [native clean-baseline plan](2026-10-02-mini-clean-upgrade-preparation.md).
No VM storage choice is required for that approved path. The preflight below
is retained as historical evidence, not an outstanding VM task.

Matt approved using a disposable macOS VM for the old-version upgrade test,
preserving the Mini's current installation and data. This pass inspected host
capacity, existing virtualization software, Apple API support and local
installer identities. It did not install software, download an OS image,
create a VM, run an installer, start product services or change network policy.

## Mini observations

| Check | Read-only result |
| --- | --- |
| Host | `matt@100.108.203.27`, macOS 27.0.1 build 26A434, ARM64 |
| Hardware | Mac16,11, Apple M4 Pro, 12 CPUs, 24 GiB RAM |
| Hypervisor | `kern.hv_support=1` |
| Storage | Internal Data volume: 460 GiB total, about 30 GiB available |
| External storage | No external data volume mounted; `/Volumes/Recovery` is not a test destination |
| Existing VM software | VirtualBox 7.2.14r174565 |
| Existing VM | `haos`, running; it was not stopped, edited or reused |
| Other checked tools | No Tart/UTM executable or VM store at the explicitly checked standard paths; this was not a whole-disk inventory |
| Product jobs | Sensor and helper remain disabled |

The capacity figures came from `sysctl` and `df`, not estimates from hardware
marketing specifications. About 30 GiB is too little margin for an OS download,
fresh VM disk, retained rollback copy and package evidence alongside the Mini's
existing workloads. An **80 GiB free-space planning budget** was proposed for
the disposable workspace; that is an operational budget, not an Apple minimum
or a guarantee that every image will fit. Recheck actual image and clone sizes
before allocating anything.

The user was asked to select an external APFS disk on the Mini or the Mac
Studio as the VM destination. No destination had been selected at this point.
Do not reclaim user files, resize partitions, reuse Recovery, stop Home
Assistant or move the test to another host without that choice.

## Important coverage correction

A macOS VM is suitable for investigating package migration, installed helper
rules and synthetic PF state, but it is not a substitute for native acceptance
of the real SSH/SMB decoys.

The current [Tart support documentation](https://tart.run/faq/#nested-virtualization-support)
limits nested virtualization to Linux VMs. The Mini's active Apple SDK exposes
the nested-virtualization controls on `VZGenericPlatformConfiguration`, not
`VZMacPlatformConfiguration`. The Xcode header copy was checked as well, with
the same distinction. This verifies the available supported configuration
surface; no macOS guest was started to make a runtime claim.

SquirrelOps' `GuestManifest.makeVirtualMachineConfiguration()` uses
`VZLinuxBootLoader`, and `VirtualMachineRuntime` requires
`VZVirtualMachine.isSupported` before starting the embedded guest. Running that
runtime inside a macOS VM would require the unsupported nesting above. A VM
upgrade result must not claim real SSH/SMB guest startup, relay behavior,
containment, or final signed-installer protocol acceptance.

The installed VirtualBox list contains x86 macOS guest types, not an ARM64
macOS type. Oracle's current
[host/guest platform matrix](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/Introduction.html)
lists Linux and Windows guests for Apple Silicon hosts. The existing Home
Assistant VM cannot be converted into this macOS acceptance environment.
No VM provider has been selected or installed; verify support, license and
artifact identity before doing so. Do not use unsupported boot modifications
to work around either limitation.

The earlier recommendation that a disposable macOS VM could complete the
remaining acceptance needs this qualification. Native real-decoy acceptance
still needs its own exact-artifact run. A separate native macOS installation
on external storage would be a different scope requiring explicit approval
for its target and reboot; the VM approval does not authorize that action.

## Verified migration inputs

The following local files were read and hashed in the existing candidate
worktree's `build/test-artifacts/` directory. Neither was installed.

| Role | Artifact | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| Historical pre-A5 candidate | `SquirrelOpsHome-2.1.0-acceptance2-20260926-local-test.pkg` | 136466581 | `7d3c8cfb5f48d8090f529fb0d94484935a7c1d1305cc02b8ee80d03425fc6853` |
| Current native-tested candidate | `SquirrelOpsHome-2.1.0-guest-resolver-20261001-local-test.pkg` | 136564700 | `47774088cd9eadc5aaddf38949e00a8b8f6eeb56c2192a5a72830d06d84a8aec` |

`pkgutil --check-signature` reports no signature for both. These match the
historical [candidate 2 record](2026-09-26-acceptance2-installer.md) and
[resolver acceptance record](2026-10-01-mini-resolver-live-result.md).
Both display 2.1.0, so version strings alone cannot distinguish them.
Candidate 2 predates the A5 fixes according to its source/build record. The
test must still observe its actual installed unconditional rules before
claiming an old-rule migration; package naming is not runtime evidence.

The newer candidate is not the final signed/notarized release artifact and
does not include the later local UI/documentation follow-up. Migration to it
would be intermediate evidence only. Do not mark final artifact acceptance
complete with either package.

## Next bounded work

1. Resolve the VM storage/host choice, inspect its capacity, and choose a
   supported ARM64 macOS VM provider and pinned OS image. Use a fresh dedicated
   workspace with no host directory shares, credentials or production data.
   Storage and rollback requirements must be satisfied before a download.
2. Prepare an isolated network and synthetic-only configuration. Do not bridge
   the old unconditional-rule candidate onto the production LAN or reuse its
   `.239/.240` addresses. Any required host-network changes need an exact
   preview and inverse operation before approval and use.
3. Install the pinned historical package inside the disposable guest. Verify
   the installed helper identity and actual old rules, establish synthetic
   TCP/PF state, then retain a stopped rollback copy. Do not assume state can
   survive a shutdown; recapture the required live state before upgrading.
4. Upgrade using the exact reviewed new package, without changing installer
   scripts to force a pass. Record installer logs, installed identities,
   rule/state cleanup, synthetic data preservation, restart and scoped cleanup.
   Do not substitute mocked install or helper behavior for the installed path.
5. Report VM migration/PF results separately from the remaining native
   real-decoy and signed-installer acceptance. The completed Mini TCP-edge
   tests are not repeated as a side effect of preparing this environment.

No code was changed or new test result claimed in this preflight. No commit,
push, merge, release or website publication occurred. The host and storage
decision is the immediate blocker, not a newly discovered product defect.
