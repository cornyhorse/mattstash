"""API key management and verification."""
import hmac
import time

from ..config import config

# Cache API keys with a TTL so rotated keys are picked up without restart
_api_keys: set[str] | None = None
_api_keys_loaded_at: float = 0.0
_CACHE_TTL_SECONDS: float = 300.0  # Re-read key source every 5 minutes


def get_valid_api_keys() -> set[str]:
    """Get the set of valid API keys (cached with TTL)."""
    global _api_keys, _api_keys_loaded_at

    now = time.monotonic()
    if _api_keys is None or (now - _api_keys_loaded_at) >= _CACHE_TTL_SECONDS:
        _api_keys = config.get_api_keys()
        _api_keys_loaded_at = now

    return _api_keys


def invalidate_api_key_cache() -> None:
    """Force the key cache to be reloaded on the next verification."""
    global _api_keys, _api_keys_loaded_at
    _api_keys = None
    _api_keys_loaded_at = 0.0


def verify_api_key(api_key: str) -> bool:
    """Verify if the provided API key is valid.

    Uses constant-time comparison to prevent timing side-channel attacks.
    """
    valid_keys = get_valid_api_keys()
    return any(
        hmac.compare_digest(api_key, valid_key)
        for valid_key in valid_keys
    )
