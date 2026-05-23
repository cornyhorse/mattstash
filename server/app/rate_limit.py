"""Rate limiter configuration."""
from slowapi import Limiter

from .config import config


def get_client_address(request) -> str:
    """Use the direct peer address so spoofed forwarding headers cannot bypass limits."""
    if request.client is None:
        return "unknown"
    return request.client.host


limiter = Limiter(key_func=get_client_address, default_limits=[config.RATE_LIMIT])
