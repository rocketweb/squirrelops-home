# Studio Mini guest

This directory builds the architecture-specific, memory-only guest used by the
2.1 deep decoy. This Linux guest contains real OpenSSH and Samba services and relays
only those services over Virtio sockets. It has no virtual NIC, persistent
disk, host directory share, clipboard, or outbound path.

Home 2.1 supports Apple Silicon (ARM64) Macs only. Intel Macs are not supported.

```bash
bash guest/studio-mini/build-guest.sh arm64
```

The output is written to `guest/studio-mini/build/<architecture>/`. Build
outputs are ignored by Git. Release automation must set `ALPINE_IMAGE` to an
immutable image digest and must build a separate bundle for `arm64` and
`x86_64`. This provides guest build coverage, not Intel Mac release support.
The supported macOS package embeds the ARM64 guest. An x86_64 guest build does
not establish Intel host runtime or installer compatibility.

The sensor creates one install-specific persona archive in memory. The signed
runtime streams it into the guest through a one-time Virtio socket before SSH
or SMB becomes reachable. Fake credentials do not need to be written to the
host filesystem.

Guest hostname and resolver files come from `network/`, not the Docker build
container. The builder copies the root filesystem into a separate staging
directory before replacing those three files, so BuildKit's injected `/etc`
files cannot override them. `studio-mini` and `studio-mini.local` resolve to
loopback; DNS is loopback-only and does not add a guest network device.

The bundle verifier streams the gzip/newc archive without extracting it. It
requires the reviewed hostname, hosts and resolver contents and rejects missing,
duplicate, linked or writable identity files, malformed archives and unexpected
trailing data. Both the guest builder and app packaging run this check.
