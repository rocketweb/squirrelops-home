"""Shared identity validation for remote pairing and local enrollment."""

MAX_CLIENT_NAME_LENGTH = 128


def validated_client_name(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Invalid client name.")
    # Inspect the original input so strip() cannot hide leading/trailing controls.
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("Invalid client name.")
    normalized = value.strip()
    if not normalized or len(normalized) > MAX_CLIENT_NAME_LENGTH:
        raise ValueError("Invalid client name.")
    return normalized
