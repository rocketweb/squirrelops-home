"""Fernet-encrypted JSON file backend for secret storage.

Used on Linux/Docker where macOS Keychain is not available. Derives an
encryption key from a master password using PBKDF2-HMAC-SHA256, then
encrypts the entire JSON secrets blob with Fernet.
"""

from __future__ import annotations

import base64
import json
import pathlib

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from squirrelops_home_sensor.secrets.store import SecretStore

# Fixed salt -- acceptable for a local-only file where the threat model is
# casual disk access, not offline brute-force against a leaked database.
_SALT = b"squirrelops-home-sensor-secrets-v1"
_ITERATIONS = 480_000


def _derive_key(master_password: str) -> bytes:
    """Derive a 32-byte Fernet key from the master password via PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_SALT,
        iterations=_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))


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
        self._fernet = Fernet(_derive_key(master_password))

    def _read_store(self) -> dict[str, str]:
        """Read and decrypt the secrets file. Returns empty dict if missing."""
        if not self._path.exists():
            return {}
        ciphertext = self._path.read_bytes()
        plaintext = self._fernet.decrypt(ciphertext)
        return json.loads(plaintext)

    def _write_store(self, data: dict[str, str]) -> None:
        """Encrypt and write the secrets to disk."""
        plaintext = json.dumps(data, sort_keys=True).encode("utf-8")
        ciphertext = self._fernet.encrypt(plaintext)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_bytes(ciphertext)

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
