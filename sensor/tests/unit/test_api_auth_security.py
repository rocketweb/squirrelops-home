"""Security invariants for development-only authentication paths."""

from squirrelops_home_sensor.api.deps import is_loopback_client


def test_only_literal_loopback_addresses_are_accepted() -> None:
    assert is_loopback_client("127.0.0.1")
    assert is_loopback_client("::1")
    assert not is_loopback_client("192.168.1.10")
    assert not is_loopback_client("localhost")
    assert not is_loopback_client("testclient")
    assert not is_loopback_client(None)
