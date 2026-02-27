"""Credential generator for decoy services.

Generates 7 types of realistic credentials planted across decoy services.
Credentials with DNS-detectable usage (AWS keys, GitHub PATs, HA tokens)
receive canary hostnames. All credential values are guaranteed unique
within a generator instance.
"""

from __future__ import annotations

import base64
import dataclasses
import os
import random
import secrets
import string
from typing import Optional


# Word lists for password generation (adjective + noun pattern)
_ADJECTIVES = [
    "happy", "brave", "quiet", "sharp", "swift", "lucky", "bold", "warm",
    "cool", "dark", "bright", "calm", "wild", "free", "soft", "deep",
    "fast", "slow", "rich", "pure", "rare", "safe", "wise", "keen",
]

_NOUNS = [
    "tiger", "river", "cloud", "stone", "flame", "ocean", "eagle", "cedar",
    "frost", "pearl", "maple", "delta", "prism", "ridge", "coral", "ember",
    "lotus", "haven", "crest", "forge", "grove", "nexus", "pulse", "vault",
]

_SYMBOLS = ["!", "@", "#", "$", "%", "&", "*"]

_USERNAMES = [
    "admin", "deploy", "backup", "jenkins", "ci-bot", "root", "svc-account",
    "dev", "staging", "dbadmin", "ops", "monitor", "scheduler", "automation",
    "build", "release", "infra", "platform", "service", "app",
]

_DB_HOSTS = [
    "db-prod-01.internal", "postgres.local", "mysql-primary.lan",
    "mongo-replica.internal", "redis-cache.local", "db.homelab.net",
]

_DB_NAMES = ["appdb", "production", "main", "homelab", "metrics", "logs"]

_ENV_VAR_TEMPLATES = [
    "DATABASE_URL={db_url}",
    "AWS_ACCESS_KEY_ID={aws_key}",
    "AWS_SECRET_ACCESS_KEY={aws_secret}",
    "API_KEY={api_key}",
    "SECRET_KEY={secret_key}",
    "REDIS_URL=redis://localhost:6379/0",
    "SMTP_PASSWORD={smtp_pass}",
    "GITHUB_TOKEN={gh_token}",
    "SENTRY_DSN=https://{sentry_key}@sentry.io/123456",
    "JWT_SECRET={jwt_secret}",
]


@dataclasses.dataclass(frozen=True)
class GeneratedCredential:
    """A single generated credential for planting in a decoy.

    Attributes:
        credential_type: One of 'password', 'aws_key', 'db_connection',
            'ssh_key', 'ha_token', 'env_file', 'github_pat'.
        credential_value: The credential content (may be multi-line for SSH keys/.env).
        planted_location: Where this credential is served (e.g. 'passwords.txt', '.env').
        canary_hostname: DNS canary hostname, if this credential type triggers DNS
            lookups when used. None for types that don't (DB strings, SSH keys).
    """

    credential_type: str
    credential_value: str
    planted_location: str
    canary_hostname: Optional[str] = None


class CredentialGenerator:
    """Generates realistic credentials for decoy services.

    Each generator instance tracks emitted values to guarantee uniqueness.
    """

    def __init__(self, *, password_filename: str = "passwords.txt") -> None:
        self._password_filename = password_filename
        self._emitted_values: set[str] = set()
        self._emitted_hostnames: set[str] = set()

    def _ensure_unique(self, value: str) -> str:
        """Raise if value was already emitted, then track it."""
        if value in self._emitted_values:
            raise RuntimeError(f"Duplicate credential value generated: {value!r}")
        self._emitted_values.add(value)
        return value

    # -----------------------------------------------------------------
    # Canary hostname
    # -----------------------------------------------------------------

    def generate_canary_hostname(self) -> str:
        """Generate a unique DNS canary hostname.

        Format: {32 hex chars}.canary.squirrelops.io
        Uses secrets.token_hex(16) for 32 hex characters.
        """
        while True:
            hostname = f"{secrets.token_hex(16)}.canary.squirrelops.io"
            if hostname not in self._emitted_hostnames:
                self._emitted_hostnames.add(hostname)
                return hostname

    # -----------------------------------------------------------------
    # passwords.txt (username:password pairs)
    # -----------------------------------------------------------------

    def generate_passwords_file(self) -> list[GeneratedCredential]:
        """Generate 8-12 username:password pairs for passwords.txt.

        Password format: adjective + noun + number(2-4 digits) + symbol.
        """
        count = random.randint(8, 12)
        creds: list[GeneratedCredential] = []
        used_usernames: set[str] = set()

        for _ in range(count):
            # Pick a unique username
            available = [u for u in _USERNAMES if u not in used_usernames]
            if not available:
                # Fallback: append a number
                username = f"user{random.randint(100, 999)}"
            else:
                username = random.choice(available)
            used_usernames.add(username)

            # Generate password: adjective + noun + number + symbol
            adj = random.choice(_ADJECTIVES).capitalize()
            noun = random.choice(_NOUNS).capitalize()
            num = str(random.randint(10, 9999))
            symbol = random.choice(_SYMBOLS)
            password = f"{adj}{noun}{num}{symbol}"

            value = self._ensure_unique(f"{username}:{password}")
            creds.append(GeneratedCredential(
                credential_type="password",
                credential_value=value,
                planted_location=self._password_filename,
            ))

        return creds

    # -----------------------------------------------------------------
    # AWS access key
    # -----------------------------------------------------------------

    def generate_aws_key(self) -> GeneratedCredential:
        """Generate a realistic AWS access key ID.

        Format: AKIA + 16 uppercase alphanumeric characters.
        Gets a canary hostname (AWS key use triggers DNS).
        """
        charset = string.ascii_uppercase + string.digits
        suffix = "".join(secrets.choice(charset) for _ in range(16))
        value = self._ensure_unique(f"AKIA{suffix}")
        return GeneratedCredential(
            credential_type="aws_key",
            credential_value=value,
            planted_location=self._password_filename,
            canary_hostname=self.generate_canary_hostname(),
        )

    # -----------------------------------------------------------------
    # Database connection string
    # -----------------------------------------------------------------

    def generate_db_connection_string(self, db_type: str) -> GeneratedCredential:
        """Generate a realistic database connection string.

        Supported db_type values: postgresql, mysql, mongodb, redis.
        No canary hostname (DB connection strings don't trigger DNS lookups
        to canary domains).
        """
        user = random.choice(["admin", "appuser", "dbuser", "root", "service"])
        password = secrets.token_urlsafe(16)
        host = random.choice(_DB_HOSTS)
        db_name = random.choice(_DB_NAMES)

        port_map = {
            "postgresql": 5432,
            "mysql": 3306,
            "mongodb": 27017,
            "redis": 6379,
        }
        port = port_map.get(db_type, 5432)
        value = self._ensure_unique(f"{db_type}://{user}:{password}@{host}:{port}/{db_name}")

        return GeneratedCredential(
            credential_type="db_connection",
            credential_value=value,
            planted_location=self._password_filename,
        )

    # -----------------------------------------------------------------
    # SSH key
    # -----------------------------------------------------------------

    def generate_ssh_key(self) -> GeneratedCredential:
        """Generate a realistic fake RSA PEM private key.

        Produces a PEM-formatted block with random base64 body.
        No canary hostname (SSH key use doesn't trigger DNS lookups
        to canary domains).
        """
        # Generate ~1600 bytes of random data (typical RSA 2048 key size)
        raw = os.urandom(1200)
        b64 = base64.b64encode(raw).decode("ascii")

        # Split into 64-char lines (PEM standard)
        lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
        pem = "-----BEGIN RSA PRIVATE KEY-----\n"
        pem += "\n".join(lines)
        pem += "\n-----END RSA PRIVATE KEY-----"

        value = self._ensure_unique(pem)
        return GeneratedCredential(
            credential_type="ssh_key",
            credential_value=value,
            planted_location="id_rsa",
        )

    # -----------------------------------------------------------------
    # Home Assistant long-lived access token
    # -----------------------------------------------------------------

    def generate_ha_token(self) -> GeneratedCredential:
        """Generate a realistic Home Assistant long-lived access token.

        Real HA tokens are 183 characters of base64-like text.
        Gets a canary hostname (HA token use triggers DNS via integrations).
        """
        charset = string.ascii_letters + string.digits + "._-"
        token = "".join(secrets.choice(charset) for _ in range(183))
        value = self._ensure_unique(token)
        return GeneratedCredential(
            credential_type="ha_token",
            credential_value=value,
            planted_location="ha_config",
            canary_hostname=self.generate_canary_hostname(),
        )

    # -----------------------------------------------------------------
    # .env file
    # -----------------------------------------------------------------

    def generate_env_file(self) -> GeneratedCredential:
        """Generate a realistic multi-line .env file with API keys.

        Contains a mix of common environment variables with fake secrets.
        """

        def _random_hex(n: int) -> str:
            return secrets.token_hex(n)

        replacements = {
            "{db_url}": f"postgresql://app:{secrets.token_urlsafe(12)}@db.local:5432/prod",
            "{aws_key}": f"AKIA{''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))}",
            "{aws_secret}": secrets.token_urlsafe(30),
            "{api_key}": f"sk-{_random_hex(24)}",
            "{secret_key}": secrets.token_urlsafe(32),
            "{smtp_pass}": secrets.token_urlsafe(16),
            "{gh_token}": f"ghp_{''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))}",
            "{sentry_key}": _random_hex(16),
            "{jwt_secret}": secrets.token_urlsafe(32),
        }

        # Pick 5-8 env vars
        count = random.randint(5, 8)
        templates = random.sample(_ENV_VAR_TEMPLATES, count)

        lines = ["# Application environment configuration", ""]
        for tmpl in templates:
            line = tmpl
            for placeholder, val in replacements.items():
                line = line.replace(placeholder, val)
            lines.append(line)

        content = "\n".join(lines)
        value = self._ensure_unique(content)
        return GeneratedCredential(
            credential_type="env_file",
            credential_value=value,
            planted_location=".env",
        )

    # -----------------------------------------------------------------
    # GitHub Personal Access Token
    # -----------------------------------------------------------------

    def generate_github_pat(self) -> GeneratedCredential:
        """Generate a realistic GitHub personal access token.

        Format: ghp_ + 36 alphanumeric characters.
        Gets a canary hostname (GitHub API calls trigger DNS).
        """
        charset = string.ascii_letters + string.digits
        suffix = "".join(secrets.choice(charset) for _ in range(36))
        value = self._ensure_unique(f"ghp_{suffix}")
        return GeneratedCredential(
            credential_type="github_pat",
            credential_value=value,
            planted_location=self._password_filename,
            canary_hostname=self.generate_canary_hostname(),
        )
