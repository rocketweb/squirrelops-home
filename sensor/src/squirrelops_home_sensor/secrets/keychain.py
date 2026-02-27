"""macOS Keychain backend for secret storage.

Wraps the macOS ``security`` CLI tool to store secrets as generic passwords
in the user's login keychain.
"""

from __future__ import annotations

import asyncio
import re

from squirrelops_home_sensor.secrets.store import SecretStore

# Exit code when a duplicate item already exists in Keychain
_ERR_DUPLICATE_ITEM = 45
# Exit code when an item is not found in Keychain
_ERR_ITEM_NOT_FOUND = 44


class KeychainStore(SecretStore):
    """Stores secrets in macOS Keychain via the ``security`` CLI.

    Parameters
    ----------
    service_name:
        The service name used to namespace secrets in Keychain.
        Defaults to ``com.squirrelops.home-sensor``.
    """

    def __init__(self, service_name: str = "com.squirrelops.home-sensor") -> None:
        self._service = service_name

    async def _run(self, *args: str) -> tuple[int, bytes, bytes]:
        """Run a ``security`` subcommand and return (returncode, stdout, stderr)."""
        proc = await asyncio.create_subprocess_exec(
            "security",
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode or 0, stdout, stderr

    async def get(self, key: str) -> str | None:
        returncode, _stdout, stderr = await self._run(
            "find-generic-password",
            "-s", self._service,
            "-a", key,
            "-g",
        )
        if returncode == _ERR_ITEM_NOT_FOUND or returncode != 0:
            return None

        # The security CLI prints the password to stderr in the form:
        #   password: "thevalue"
        stderr_str = stderr.decode("utf-8", errors="replace")
        match = re.search(r'password:\s*"(.+)"', stderr_str)
        if match:
            return match.group(1)
        return None

    async def set(self, key: str, value: str) -> None:
        returncode, _, _ = await self._run(
            "add-generic-password",
            "-s", self._service,
            "-a", key,
            "-w", value,
            "-U",
        )
        if returncode == _ERR_DUPLICATE_ITEM:
            # Delete existing and re-add
            await self._run(
                "delete-generic-password",
                "-s", self._service,
                "-a", key,
            )
            await self._run(
                "add-generic-password",
                "-s", self._service,
                "-a", key,
                "-w", value,
            )

    async def delete(self, key: str) -> None:
        await self._run(
            "delete-generic-password",
            "-s", self._service,
            "-a", key,
        )
        # Silently ignore errSecItemNotFound

    async def list_keys(self) -> list[str]:
        returncode, stdout, _ = await self._run("dump-keychain")
        if returncode != 0:
            return []

        output = stdout.decode("utf-8", errors="replace")
        keys: list[str] = []
        lines = output.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            # Look for service name match, then find the account in the same block
            if f'"svce"<blob>="{self._service}"' in line:
                for j in range(i + 1, min(i + 5, len(lines))):
                    acct_match = re.search(r'"acct"<blob>="(.+?)"', lines[j])
                    if acct_match:
                        keys.append(acct_match.group(1))
                        break
            # Also check if account comes before service in the same block
            if '"acct"<blob>=' in line:
                acct_match = re.search(r'"acct"<blob>="(.+?)"', line)
                if acct_match:
                    for j in range(max(0, i - 3), min(i + 5, len(lines))):
                        if (
                            f'"svce"<blob>="{self._service}"' in lines[j]
                            and j != i
                        ):
                            candidate = acct_match.group(1)
                            if candidate not in keys:
                                keys.append(candidate)
                            break
            i += 1
        return keys
