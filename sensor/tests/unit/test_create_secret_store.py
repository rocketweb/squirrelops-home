"""Tests for create_secret_store passphrase resolution and legacy migration."""

from __future__ import annotations

import base64
import json
import pathlib

import pytest
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from squirrelops_home_sensor.__main__ import create_secret_store
from squirrelops_home_sensor.secrets.encrypted_file import (
    _ITERATIONS,
    _LEGACY_SALT,
    EncryptedFileStore,
)

_ENV = "SQUIRRELOPS_SECRET_PASSPHRASE"


def _config(data_dir: pathlib.Path) -> dict:
    return {"sensor": {"data_dir": str(data_dir)}}


def _write_legacy_store(path: pathlib.Path, password: str, data: dict) -> None:
    """Write a store in the legacy raw-Fernet (fixed-salt) on-disk format."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=_LEGACY_SALT, iterations=_ITERATIONS)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(Fernet(key).encrypt(json.dumps(data).encode()))


@pytest.mark.asyncio
async def test_env_var_passphrase_takes_precedence(tmp_path, monkeypatch):
    monkeypatch.setenv(_ENV, "env-supplied-passphrase")
    store = create_secret_store(_config(tmp_path))
    await store.set("k", "v")

    # No passphrase is persisted to disk when supplied via the environment.
    assert not (tmp_path / ".secret_passphrase").exists()
    # The store is keyed by the env passphrase.
    reopened = EncryptedFileStore(tmp_path / "secrets.enc", "env-supplied-passphrase")
    assert await reopened.get("k") == "v"


@pytest.mark.asyncio
async def test_legacy_default_store_is_migrated_off_hardcoded_key(tmp_path, monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)
    secrets_file = tmp_path / "secrets.enc"
    _write_legacy_store(secrets_file, "squirrelops-default", {"old": "secret"})

    store = create_secret_store(_config(tmp_path))

    # A fresh random passphrase is now persisted (and is not the hardcoded one).
    passphrase_file = tmp_path / ".secret_passphrase"
    assert passphrase_file.exists()
    assert passphrase_file.read_text().strip() != "squirrelops-default"

    # Existing data survives the migration...
    assert await store.get("old") == "secret"
    # ...and the hardcoded default can no longer decrypt the store.
    stale = EncryptedFileStore(secrets_file, "squirrelops-default")
    with pytest.raises(InvalidToken):
        await stale.get("old")


@pytest.mark.asyncio
async def test_legacy_store_undecryptable_fails_closed(tmp_path, monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)
    secrets_file = tmp_path / "secrets.enc"
    # A store that is NOT encrypted with the legacy default and has no passphrase.
    _write_legacy_store(secrets_file, "some-other-password", {"old": "secret"})

    with pytest.raises(RuntimeError):
        create_secret_store(_config(tmp_path))
