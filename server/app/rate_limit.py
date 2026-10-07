"""Rate limiter configuration."""

from typing import Any

from slowapi import Limiter

from .client_ip import client_ip
from .config import config


def get_client_address(request: Any) -> str:
    """Rate-limit identity: the TCP peer, or the proxy-reported client if trusted hops are configured."""
    return client_ip(request.scope)


def read_limit() -> str:
    """Limit for read endpoints (``MATTSTASH_RATE_LIMIT``); evaluated per request so it can be reconfigured."""
    return config.RATE_LIMIT


limiter = Limiter(key_func=get_client_address, default_limits=[config.RATE_LIMIT])
