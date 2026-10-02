"""Minimal gzip/newc fixtures for guest packaging checks, never extracted."""

import gzip
import stat

NETWORK_FILES = {
    "etc/hosts": b"127.0.0.1 studio-mini.local studio-mini localhost\n"
                 b"::1 localhost ip6-localhost ip6-loopback\n",
    "etc/hostname": b"studio-mini\n",
    "etc/resolv.conf": b"nameserver 127.0.0.1\noptions timeout:1 attempts:1\n",
}


def initramfs(entries=None):
    if entries is None:
        entries = [(name, content, stat.S_IFREG | 0o644, 1)
                   for name, content in NETWORK_FILES.items()]
    archive = bytearray()
    for inode, (name, content, mode, links) in enumerate(
        [*entries, ("TRAILER!!!", b"", 0, 1)], 1
    ):
        encoded = name.encode() + b"\0"
        fields = [inode, mode, 0, 0, links, 0, len(content), 0, 0, 0, 0, len(encoded), 0]
        archive += b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
        archive += encoded
        archive += b"\0" * (-len(archive) % 4)
        archive += content
        archive += b"\0" * (-len(archive) % 4)
    return gzip.compress(archive, mtime=0)
