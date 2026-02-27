"""Rate limiter configuration."""
from slowapi import Limiter
from slowapi.util import get_remote_address

from .config import config

limiter = Limiter(key_func=get_remote_address, default_limits=[config.RATE_LIMIT])
