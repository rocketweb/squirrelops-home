"""Fernet-encrypted JSON file backend for secret storage.

Used on Linux/Docker where macOS Keychain is not available. Derives an
encryption key from a master password using PBKDF2-HMAC-SHA256, then
encrypts the entire JSON secrets blob with Fernet.

On-disk format (current): ``MAGIC (4 bytes) || salt (16 bytes) || Fernet token``.
A random per-store salt means two installs that happen to share a passphrase
do not share a derived key, so a single precomputation cannot attack many
stores. Files written by older versions (a bare Fernet token derived with a
fixed salt) are still readable and are transparently migrated to the salted
format on the next write.
"""

from __future__ import annotations

import base64
import json
import os
import pathlib

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from squirrelops_home_sensor.fsutil import write_bytes_atomic
from squirrelops_home_sensor.secrets.store import SecretStore

# Format marker for the salted layout. Legacy files (no marker) used a fixed
# salt and are read with _LEGACY_SALT for backward compatibility.
_MAGIC = b"SQE1"
_SALT_LEN = 16
_LEGACY_SALT = b"squirrelops-home-sensor-secrets-v1"
_ITERATIONS = 480_000


def _derive_fernet(master_password: str, salt: bytes) -> Fernet:
    """Derive a Fernet instance from the master password and salt via PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))
    return Fernet(key)


class EncryptedFileStore(SecretStore):
    """Stores secrets as a Fernet-encrypted JSON file on disk.

    Parameters
    ----------
    file_path:
        Path to the encrypted secrets file. Created on first write.
    master_password:
        Password used to derive the Fernet encryption key via PBKDF2.
    """

    def __init__(self, file_path: pathlib.Path, master_password: str) -> None:
        self._path = file_path
        self._master_password = master_password
        # Cache the salt and derived Fernet for this store so repeated reads and
        # writes do not re-run the expensive KDF. Populated lazily.
        self._salt: bytes | None = None
        self._fernet: Fernet | None = None

    def _fernet_for(self, salt: bytes) -> Fernet:
        if self._fernet is None or self._salt != salt:
            self._salt = salt
            self._fernet = _derive_fernet(self._master_password, salt)
        return self._fernet

    def _read_store(self) -> dict[str, str]:
        """Read and decrypt the secrets file. Returns empty dict if missing."""
        if not self._path.exists():
            return {}
        raw = self._path.read_bytes()
        if raw.startswith(_MAGIC):
            salt = raw[len(_MAGIC):len(_MAGIC) + _SALT_LEN]
            ciphertext = raw[len(_MAGIC) + _SALT_LEN:]
            fernet = self._fernet_for(salt)
        else:
            # Legacy format: bare Fernet token derived with the fixed salt.
            fernet = _derive_fernet(self._master_password, _LEGACY_SALT)
            ciphertext = raw
        plaintext = fernet.decrypt(ciphertext)
        return json.loads(plaintext)

    def _current_salt(self) -> bytes:
        """Return the salt to write with: reuse the store's existing salt, else
        generate a fresh random one (migrating legacy files in the process)."""
        if self._salt is not None:
            return self._salt
        if self._path.exists():
            head = self._path.read_bytes()[: len(_MAGIC) + _SALT_LEN]
            if head.startswith(_MAGIC):
                return head[len(_MAGIC):len(_MAGIC) + _SALT_LEN]
        return os.urandom(_SALT_LEN)

    def _write_store(self, data: dict[str, str]) -> None:
        """Encrypt and atomically write the secrets to disk (owner-only)."""
        salt = self._current_salt()
        fernet = self._fernet_for(salt)
        plaintext = json.dumps(data, sort_keys=True).encode("utf-8")
        ciphertext = fernet.encrypt(plaintext)
        write_bytes_atomic(self._path, _MAGIC + salt + ciphertext, mode=0o600)

    async def get(self, key: str) -> str | None:
        store = self._read_store()
        return store.get(key)

    async def set(self, key: str, value: str) -> None:
        store = self._read_store()
        store[key] = value
        self._write_store(store)

    async def delete(self, key: str) -> None:
        store = self._read_store()
        store.pop(key, None)
        self._write_store(store)

    async def list_keys(self) -> list[str]:
        store = self._read_store()
        return list(store.keys())


def reencrypt_store(
    file_path: pathlib.Path, *, old_password: str, new_password: str
) -> bool:
    """Re-encrypt an existing store under a new password and a fresh salt.

    Reads the store with ``old_password`` (supporting the legacy fixed-salt
    format) and rewrites it with ``new_password`` in the salted format. Returns
    True if a store existed and was migrated, False if there was no store file.
    Raises ``cryptography.fernet.InvalidToken`` if ``old_password`` is wrong.
    """
    if not file_path.exists():
        return False
    source = EncryptedFileStore(file_path, old_password)
    data = source._read_store()
    dest = EncryptedFileStore(file_path, new_password)
    dest._write_store(data)  # fresh random salt, owner-only perms
    return True
