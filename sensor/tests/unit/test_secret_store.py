"""Tests for the secret store abstraction and backends."""

from __future__ import annotations

import asyncio
import json
import pathlib
import re
from unittest.mock import AsyncMock, patch

import pytest

from squirrelops_home_sensor.secrets.store import SecretStore
from squirrelops_home_sensor.secrets.encrypted_file import EncryptedFileStore
from squirrelops_home_sensor.secrets.keychain import KeychainStore


# ---------------------------------------------------------------------------
# SecretStore ABC contract
# ---------------------------------------------------------------------------

class TestSecretStoreABC:
    """Verify the abstract interface cannot be instantiated directly."""

    def test_cannot_instantiate_abstract(self) -> None:
        with pytest.raises(TypeError):
            SecretStore()  # type: ignore[abstract]

    def test_has_required_methods(self) -> None:
        methods = {"get", "set", "delete", "list_keys"}
        for method in methods:
            assert hasattr(SecretStore, method), f"SecretStore must define {method}"


# ---------------------------------------------------------------------------
# EncryptedFileStore
# ---------------------------------------------------------------------------

class TestEncryptedFileStore:
    """Test Fernet-encrypted JSON file backend."""

    @pytest.fixture
    def store(self, tmp_path: pathlib.Path) -> EncryptedFileStore:
        return EncryptedFileStore(
            file_path=tmp_path / "secrets.enc",
            master_password="test-master-password-123",
        )

    @pytest.mark.asyncio
    async def test_set_and_get_secret(self, store: EncryptedFileStore) -> None:
        await store.set("api_key", "sk-abc123")
        result = await store.get("api_key")
        assert result == "sk-abc123"

    @pytest.mark.asyncio
    async def test_get_nonexistent_returns_none(self, store: EncryptedFileStore) -> None:
        result = await store.get("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_secret(self, store: EncryptedFileStore) -> None:
        await store.set("api_key", "sk-abc123")
        await store.delete("api_key")
        result = await store.get("api_key")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent_does_not_raise(
        self, store: EncryptedFileStore
    ) -> None:
        await store.delete("nonexistent")  # Should not raise

    @pytest.mark.asyncio
    async def test_list_keys_empty(self, store: EncryptedFileStore) -> None:
        keys = await store.list_keys()
        assert keys == []

    @pytest.mark.asyncio
    async def test_list_keys_returns_all(self, store: EncryptedFileStore) -> None:
        await store.set("key_a", "value_a")
        await store.set("key_b", "value_b")
        await store.set("key_c", "value_c")
        keys = await store.list_keys()
        assert sorted(keys) == ["key_a", "key_b", "key_c"]

    @pytest.mark.asyncio
    async def test_overwrite_existing_key(self, store: EncryptedFileStore) -> None:
        await store.set("api_key", "old_value")
        await store.set("api_key", "new_value")
        result = await store.get("api_key")
        assert result == "new_value"

    @pytest.mark.asyncio
    async def test_encrypted_file_roundtrip_persistence(
        self, tmp_path: pathlib.Path
    ) -> None:
        """Verify data persists across separate store instances."""
        file_path = tmp_path / "secrets.enc"
        password = "roundtrip-password"

        store1 = EncryptedFileStore(file_path=file_path, master_password=password)
        await store1.set("persistent_key", "persistent_value")

        store2 = EncryptedFileStore(file_path=file_path, master_password=password)
        result = await store2.get("persistent_key")
        assert result == "persistent_value"

    @pytest.mark.asyncio
    async def test_wrong_password_raises(self, tmp_path: pathlib.Path) -> None:
        """Verify that the wrong master password fails to decrypt."""
        file_path = tmp_path / "secrets.enc"

        store1 = EncryptedFileStore(file_path=file_path, master_password="correct")
        await store1.set("key", "value")

        store2 = EncryptedFileStore(file_path=file_path, master_password="wrong")
        with pytest.raises(Exception):
            await store2.get("key")

    @pytest.mark.asyncio
    async def test_file_is_not_plaintext(self, tmp_path: pathlib.Path) -> None:
        """Verify the stored file is actually encrypted, not plain JSON."""
        file_path = tmp_path / "secrets.enc"
        store = EncryptedFileStore(file_path=file_path, master_password="pw")
        await store.set("secret", "super-secret-value")

        raw = file_path.read_bytes()
        assert b"super-secret-value" not in raw
        assert b"secret" not in raw

    @pytest.mark.asyncio
    async def test_stores_multiple_secrets(self, store: EncryptedFileStore) -> None:
        await store.set("key1", "val1")
        await store.set("key2", "val2")
        await store.set("key3", "val3")
        assert await store.get("key1") == "val1"
        assert await store.get("key2") == "val2"
        assert await store.get("key3") == "val3"


# ---------------------------------------------------------------------------
# KeychainStore (mocked macOS security CLI)
# ---------------------------------------------------------------------------

class TestKeychainStore:
    """Test macOS Keychain backend with mocked subprocess calls."""

    @pytest.fixture
    def store(self) -> KeychainStore:
        return KeychainStore(service_name="com.squirrelops.test")

    @pytest.mark.asyncio
    async def test_set_calls_security_add(self, store: KeychainStore) -> None:
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            await store.set("api_key", "sk-abc123")

            mock_exec.assert_called_once()
            call_args = mock_exec.call_args[0]
            assert call_args[0] == "security"
            assert "add-generic-password" in call_args
            assert "-s" in call_args
            assert "com.squirrelops.test" in call_args
            assert "-a" in call_args
            assert "api_key" in call_args
            assert "-w" in call_args
            assert "sk-abc123" in call_args

    @pytest.mark.asyncio
    async def test_set_updates_existing_on_duplicate(
        self, store: KeychainStore
    ) -> None:
        """When add fails with errSecDuplicateItem (exit 45), delete then re-add."""
        call_count = 0

        async def mock_exec(*args: object, **kwargs: object) -> AsyncMock:
            nonlocal call_count
            call_count += 1
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            if call_count == 1:
                # First add-generic-password fails (duplicate)
                mock_proc.returncode = 45
            else:
                mock_proc.returncode = 0
            return mock_proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            await store.set("api_key", "sk-new")
            # Should have called: add (fail), delete, add (success) = 3 calls
            assert call_count == 3

    @pytest.mark.asyncio
    async def test_get_calls_security_find(self, store: KeychainStore) -> None:
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(
            return_value=(b"", b'password: "sk-abc123"\n')
        )

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            result = await store.get("api_key")

            mock_exec.assert_called_once()
            call_args = mock_exec.call_args[0]
            assert call_args[0] == "security"
            assert "find-generic-password" in call_args
            assert "api_key" in call_args
            assert result == "sk-abc123"

    @pytest.mark.asyncio
    async def test_get_nonexistent_returns_none(self, store: KeychainStore) -> None:
        mock_proc = AsyncMock()
        mock_proc.returncode = 44  # errSecItemNotFound
        mock_proc.communicate = AsyncMock(
            return_value=(b"", b"security: SecKeychainSearchCopyNext: not found\n")
        )

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await store.get("nonexistent")
            assert result is None

    @pytest.mark.asyncio
    async def test_delete_calls_security_delete(self, store: KeychainStore) -> None:
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            await store.delete("api_key")

            mock_exec.assert_called_once()
            call_args = mock_exec.call_args[0]
            assert call_args[0] == "security"
            assert "delete-generic-password" in call_args
            assert "api_key" in call_args

    @pytest.mark.asyncio
    async def test_delete_nonexistent_does_not_raise(
        self, store: KeychainStore
    ) -> None:
        mock_proc = AsyncMock()
        mock_proc.returncode = 44
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            await store.delete("nonexistent")  # Should not raise

    @pytest.mark.asyncio
    async def test_list_keys_parses_dump_output(self, store: KeychainStore) -> None:
        dump_output = (
            b'keychain: "/Users/test/Library/Keychains/login.keychain-db"\n'
            b'class: "genp"\n'
            b'    "svce"<blob>="com.squirrelops.test"\n'
            b'    "acct"<blob>="key_one"\n'
            b'class: "genp"\n'
            b'    "svce"<blob>="com.squirrelops.test"\n'
            b'    "acct"<blob>="key_two"\n'
            b'class: "genp"\n'
            b'    "svce"<blob>="com.other.service"\n'
            b'    "acct"<blob>="key_three"\n'
        )
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(dump_output, b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            keys = await store.list_keys()
            assert sorted(keys) == ["key_one", "key_two"]

    @pytest.mark.asyncio
    async def test_list_keys_empty_keychain(self, store: KeychainStore) -> None:
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            keys = await store.list_keys()
            assert keys == []
