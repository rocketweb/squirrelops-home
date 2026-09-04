# Studio Mini guest

This directory builds the architecture-specific, memory-only guest used by the
2.1 deep decoy. The guest contains real OpenSSH and Samba services and relays
only those services over Virtio sockets. It has no virtual NIC, persistent
disk, host directory share, clipboard, or outbound path.

```bash
bash guest/studio-mini/build-guest.sh arm64
```

The output is written to `guest/studio-mini/build/<architecture>/`. Build
outputs are ignored by Git. Release automation must set `ALPINE_IMAGE` to an
immutable image digest and must build a separate bundle for `arm64` and
`x86_64`.

The sensor creates one install-specific persona archive in memory. The signed
runtime streams it into the guest through a one-time Virtio socket before SSH
or SMB becomes reachable. Fake credentials do not need to be written to the
host filesystem.
