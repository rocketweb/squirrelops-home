"""Adaptive throttle stub for ClownPeanuts tarpit functionality."""


class AdaptiveThrottle:
    """Stub for the adaptive throttle used by the tarpit system.

    In the full ClownPeanuts implementation, this would slow down
    attacker connections progressively. For the sensor stub, it's a no-op.
    """

    def __init__(self, **kwargs):
        pass

    def should_throttle(self, client_ip: str) -> bool:
        return False

    def record_request(self, client_ip: str) -> None:
        pass
