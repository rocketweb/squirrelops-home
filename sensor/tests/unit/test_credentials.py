"""Unit tests for the credential generator.

Covers all 7 credential types, format correctness, uniqueness guarantees,
and DNS canary hostname generation.
"""

import re
import secrets
from unittest.mock import patch

import pytest

from squirrelops_home_sensor.decoys.credentials import (
    CredentialGenerator,
    GeneratedCredential,
)


# ---------------------------------------------------------------------------
# GeneratedCredential dataclass
# ---------------------------------------------------------------------------

class TestGeneratedCredential:
    """Verify the GeneratedCredential structure."""

    def test_required_fields(self):
        """Credential must have credential_type, credential_value, planted_location."""
        cred = GeneratedCredential(
            credential_type="aws_key",
            credential_value="AKIAIOSFODNN7EXAMPLE",
            planted_location="passwords.txt",
        )
        assert cred.credential_type == "aws_key"
        assert cred.credential_value == "AKIAIOSFODNN7EXAMPLE"
        assert cred.planted_location == "passwords.txt"

    def test_canary_hostname_defaults_none(self):
        """canary_hostname should default to None."""
        cred = GeneratedCredential(
            credential_type="ssh_key",
            credential_value="-----BEGIN RSA PRIVATE KEY-----",
            planted_location="id_rsa",
        )
        assert cred.canary_hostname is None

    def test_canary_hostname_set(self):
        """canary_hostname should accept a value."""
        cred = GeneratedCredential(
            credential_type="aws_key",
            credential_value="AKIAIOSFODNN7EXAMPLE",
            planted_location="passwords.txt",
            canary_hostname="abc123.canary.squirrelops.io",
        )
        assert cred.canary_hostname == "abc123.canary.squirrelops.io"


# ---------------------------------------------------------------------------
# passwords.txt generation (username:password pairs)
# ---------------------------------------------------------------------------

class TestPasswordsFile:
    """generate_passwords_file() produces realistic username:password pairs."""

    @pytest.fixture
    def generator(self):
        return CredentialGenerator()

    def test_returns_list_of_credentials(self, generator):
        """Should return a list of GeneratedCredential objects."""
        creds = generator.generate_passwords_file()
        assert isinstance(creds, list)
        assert all(isinstance(c, GeneratedCredential) for c in creds)

    def test_count_between_8_and_12(self, generator):
        """passwords.txt should contain 8-12 entries."""
        creds = generator.generate_passwords_file()
        assert 8 <= len(creds) <= 12

    def test_credential_type_is_password(self, generator):
        """All entries should have credential_type='password'."""
        creds = generator.generate_passwords_file()
        for cred in creds:
            assert cred.credential_type == "password"

    def test_planted_location_is_passwords_txt(self, generator):
        """All entries should be planted in 'passwords.txt'."""
        creds = generator.generate_passwords_file()
        for cred in creds:
            assert cred.planted_location == "passwords.txt"

    def test_custom_password_filename(self):
        """CredentialGenerator uses custom filename for password credentials."""
        gen = CredentialGenerator(password_filename="secrets.txt")
        creds = gen.generate_passwords_file()
        for cred in creds:
            assert cred.planted_location == "secrets.txt"

    def test_value_format_username_colon_password(self, generator):
        """Each value should be in 'username:password' format."""
        creds = generator.generate_passwords_file()
        for cred in creds:
            parts = cred.credential_value.split(":", 1)
            assert len(parts) == 2, f"Expected 'user:pass' format, got: {cred.credential_value}"
            assert len(parts[0]) > 0
            assert len(parts[1]) > 0

    def test_password_has_adjective_noun_number_symbol(self, generator):
        """Password portion should follow adjective+noun+number+symbol pattern."""
        creds = generator.generate_passwords_file()
        # Pattern: word chars, then digits, then a symbol character
        pattern = re.compile(r"^[A-Za-z]+[0-9]+[^A-Za-z0-9]+$")
        for cred in creds:
            password = cred.credential_value.split(":", 1)[1]
            assert pattern.match(password), (
                f"Password '{password}' does not match adjective+noun+number+symbol pattern"
            )


# ---------------------------------------------------------------------------
# AWS key generation
# ---------------------------------------------------------------------------

class TestAWSKey:
    """generate_aws_key() produces realistic AWS access key IDs."""

    @pytest.fixture
    def generator(self):
        return CredentialGenerator()

    def test_returns_credential(self, generator):
        cred = generator.generate_aws_key()
        assert isinstance(cred, GeneratedCredential)

    def test_type_is_aws_key(self, generator):
        cred = generator.generate_aws_key()
        assert cred.credential_type == "aws_key"

    def test_starts_with_akia(self, generator):
        """AWS access key IDs start with AKIA."""
        cred = generator.generate_aws_key()
        assert cred.credential_value.startswith("AKIA")

    def test_total_length_20(self, generator):
        """AWS access key IDs are exactly 20 characters."""
        cred = generator.generate_aws_key()
        assert len(cred.credential_value) == 20

    def test_suffix_is_uppercase_alphanumeric(self, generator):
        """Characters after AKIA should be uppercase letters and digits."""
        cred = generator.generate_aws_key()
        suffix = cred.credential_value[4:]
        assert re.match(r"^[A-Z0-9]{16}$", suffix)

    def test_has_canary_hostname(self, generator):
        """AWS keys should get a canary hostname (DNS-detectable)."""
        cred = generator.generate_aws_key()
        assert cred.canary_hostname is not None
        assert cred.canary_hostname.endswith(".canary.squirrelops.io")

    def test_planted_location(self, generator):
        cred = generator.generate_aws_key()
        assert cred.planted_location == "passwords.txt"


# ---------------------------------------------------------------------------
# Database connection string generation
# ---------------------------------------------------------------------------

class TestDBConnectionStrings:
    """generate_db_connection_string() produces realistic DB URIs."""

    @pytest.fixture
    def generator(self):
        return CredentialGenerator()

    @pytest.mark.parametrize("db_type,scheme", [
        ("postgresql", "postgresql://"),
        ("mysql", "mysql://"),
        ("mongodb", "mongodb://"),
        ("redis", "redis://"),
    ])
    def test_scheme_matches_db_type(self, generator, db_type, scheme):
        """Connection string must start with the correct scheme."""
        cred = generator.generate_db_connection_string(db_type)
        assert cred.credential_value.startswith(scheme)

    def test_type_is_db_connection(self, generator):
        cred = generator.generate_db_connection_string("postgresql")
        assert cred.credential_type == "db_connection"

    def test_contains_fake_password(self, generator):
        """Connection string must include a password component."""
        cred = generator.generate_db_connection_string("postgresql")
        # URI format: scheme://user:password@host:port/db
        assert ":" in cred.credential_value.split("://")[1].split("@")[0]

    def test_planted_location(self, generator):
        cred = generator.generate_db_connection_string("mysql")
        assert cred.planted_location == "passwords.txt"

    def test_no_canary_hostname(self, generator):
        """DB strings don't trigger DNS lookups — no canary hostname."""
        cred = generator.generate_db_connection_string("postgresql")
        assert cred.canary_hostname is None


# ---------------------------------------------------------------------------
# SSH key generation
# ---------------------------------------------------------------------------

class TestSSHKey:
    """generate_ssh_key() produces a realistic RSA PEM private key."""

    @pytest.fixture
    def generator(self):
        return CredentialGenerator()

    def test_returns_credential(self, generator):
        cred = generator.generate_ssh_key()
        assert isinstance(cred, GeneratedCredential)

    def test_type_is_ssh_key(self, generator):
        cred = generator.generate_ssh_key()
        assert cred.credential_type == "ssh_key"

    def test_pem_header_and_footer(self, generator):
        """SSH key should have RSA PEM format markers."""
        cred = generator.generate_ssh_key()
        assert "-----BEGIN RSA PRIVATE KEY-----" in cred.credential_value
        assert "-----END RSA PRIVATE KEY-----" in cred.credential_value

    def test_contains_base64_body(self, generator):
        """Body between markers should be base64-encoded lines."""
        cred = generator.generate_ssh_key()
        lines = cred.credential_value.strip().split("\n")
        # Skip header and footer
        body_lines = lines[1:-1]
        assert len(body_lines) > 0
        for line in body_lines:
            assert re.match(r"^[A-Za-z0-9+/=]+$", line), f"Invalid base64 line: {line}"

    def test_planted_location_is_id_rsa(self, generator):
        cred = generator.generate_ssh_key()
        assert cred.planted_location == "id_rsa"

    def test_no_canary_hostname(self, generator):
        """SSH keys don't trigger DNS lookups — no canary hostname."""
        cred = generator.generate_ssh_key()
        assert cred.canary_hostname is None


# ---------------------------------------------------------------------------
# Home Assistant token generation
# ---------------------------------------------------------------------------

class TestHAToken:
    """generate_ha_token() produces a realistic HA long-lived access token."""

    @pytest.fixture
    def generator(self):
        return CredentialGenerator()

    def test_returns_credential(self, generator):
        cred = generator.generate_ha_token()
        assert isinstance(cred, GeneratedCredential)

    def test_type_is_ha_token(self, generator):
        cred = generator.generate_ha_token()
        assert cred.credential_type == "ha_token"

    def test_length_is_183(self, generator):
        """Real HA tokens are 183 characters of base64-like text."""
        cred = generator.generate_ha_token()
        assert len(cred.credential_value) == 183

    def test_base64_like_characters(self, generator):
        """Token should only contain base64-safe characters."""
        cred = generator.generate_ha_token()
        assert re.match(r"^[A-Za-z0-9._-]+$", cred.credential_value)

    def test_has_canary_hostname(self, generator):
        """HA tokens should get a canary hostname (DNS-detectable)."""
        cred = generator.generate_ha_token()
        assert cred.canary_hostname is not None
        assert cred.canary_hostname.endswith(".canary.squirrelops.io")

    def test_planted_location(self, generator):
        cred = generator.generate_ha_token()
        assert cred.planted_location == "ha_config"


# ---------------------------------------------------------------------------
# .env file generation
# ---------------------------------------------------------------------------

class TestEnvFile:
    """generate_env_file() produces a realistic multi-line .env file."""

    @pytest.fixture
    def generator(self):
        return CredentialGenerator()

    def test_returns_credential(self, generator):
        cred = generator.generate_env_file()
        assert isinstance(cred, GeneratedCredential)

    def test_type_is_env_file(self, generator):
        cred = generator.generate_env_file()
        assert cred.credential_type == "env_file"

    def test_multiline_format(self, generator):
        """Value should contain multiple KEY=value lines."""
        cred = generator.generate_env_file()
        lines = [l for l in cred.credential_value.strip().split("\n") if l and not l.startswith("#")]
        assert len(lines) >= 3

    def test_contains_api_key_variables(self, generator):
        """Should include API-key-like environment variables."""
        cred = generator.generate_env_file()
        content = cred.credential_value
        # Should have at least some common env var patterns
        has_key_var = any(
            key in content
            for key in ["API_KEY", "SECRET", "TOKEN", "DATABASE_URL", "AWS_"]
        )
        assert has_key_var, f"Expected API key variables in .env content: {content}"

    def test_planted_location_is_dot_env(self, generator):
        cred = generator.generate_env_file()
        assert cred.planted_location == ".env"


# ---------------------------------------------------------------------------
# GitHub PAT generation
# ---------------------------------------------------------------------------

class TestGitHubPAT:
    """generate_github_pat() produces a realistic GitHub personal access token."""

    @pytest.fixture
    def generator(self):
        return CredentialGenerator()

    def test_returns_credential(self, generator):
        cred = generator.generate_github_pat()
        assert isinstance(cred, GeneratedCredential)

    def test_type_is_github_pat(self, generator):
        cred = generator.generate_github_pat()
        assert cred.credential_type == "github_pat"

    def test_starts_with_ghp_prefix(self, generator):
        """GitHub PATs start with 'ghp_'."""
        cred = generator.generate_github_pat()
        assert cred.credential_value.startswith("ghp_")

    def test_total_length_40(self, generator):
        """ghp_ (4 chars) + 36 alphanumeric = 40 total."""
        cred = generator.generate_github_pat()
        assert len(cred.credential_value) == 40

    def test_suffix_is_alphanumeric(self, generator):
        """Characters after ghp_ should be alphanumeric."""
        cred = generator.generate_github_pat()
        suffix = cred.credential_value[4:]
        assert re.match(r"^[A-Za-z0-9]{36}$", suffix)

    def test_has_canary_hostname(self, generator):
        """GitHub PATs should get a canary hostname (DNS-detectable)."""
        cred = generator.generate_github_pat()
        assert cred.canary_hostname is not None
        assert cred.canary_hostname.endswith(".canary.squirrelops.io")

    def test_planted_location(self, generator):
        cred = generator.generate_github_pat()
        assert cred.planted_location == "passwords.txt"


# ---------------------------------------------------------------------------
# Canary hostname generation
# ---------------------------------------------------------------------------

class TestCanaryHostname:
    """generate_canary_hostname() produces unique .canary.squirrelops.io hostnames."""

    @pytest.fixture
    def generator(self):
        return CredentialGenerator()

    def test_format(self, generator):
        """Hostname should be {hex}.canary.squirrelops.io."""
        hostname = generator.generate_canary_hostname()
        assert hostname.endswith(".canary.squirrelops.io")
        subdomain = hostname.replace(".canary.squirrelops.io", "")
        assert re.match(r"^[0-9a-f]{32}$", subdomain), (
            f"Subdomain should be 32 hex chars, got: {subdomain}"
        )

    def test_uniqueness(self, generator):
        """Multiple calls should produce unique hostnames."""
        hostnames = {generator.generate_canary_hostname() for _ in range(50)}
        assert len(hostnames) == 50


# ---------------------------------------------------------------------------
# Cross-type uniqueness
# ---------------------------------------------------------------------------

class TestUniqueness:
    """Credentials generated by the same generator instance must be unique."""

    def test_all_credential_values_unique(self):
        """No two generated credentials should share the same value."""
        generator = CredentialGenerator()
        values = set()

        # Generate one of each type
        for cred in generator.generate_passwords_file():
            assert cred.credential_value not in values, f"Duplicate: {cred.credential_value}"
            values.add(cred.credential_value)

        for method in [
            generator.generate_aws_key,
            generator.generate_ssh_key,
            generator.generate_ha_token,
            generator.generate_env_file,
            generator.generate_github_pat,
        ]:
            cred = method()
            assert cred.credential_value not in values, f"Duplicate: {cred.credential_value}"
            values.add(cred.credential_value)

    def test_canary_hostnames_unique(self):
        """All credentials with canary hostnames should have unique hostnames."""
        generator = CredentialGenerator()
        hostnames = set()

        aws = generator.generate_aws_key()
        if aws.canary_hostname:
            hostnames.add(aws.canary_hostname)

        ha = generator.generate_ha_token()
        if ha.canary_hostname:
            assert ha.canary_hostname not in hostnames
            hostnames.add(ha.canary_hostname)

        gh = generator.generate_github_pat()
        if gh.canary_hostname:
            assert gh.canary_hostname not in hostnames
            hostnames.add(gh.canary_hostname)

        assert len(hostnames) == 3
