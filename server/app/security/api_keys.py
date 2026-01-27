"""API key management and verification."""
from ..config import config


# Cache API keys
_api_keys: set[str] | None = None


def get_valid_api_keys() -> set[str]:
    """Get the set of valid API keys (cached)."""
    global _api_keys
    
    if _api_keys is None:
        _api_keys = config.get_api_keys()
    
    return _api_keys


def verify_api_key(api_key: str) -> bool:
    """Verify if the provided API key is valid."""
    valid_keys = get_valid_api_keys()
    return api_key in valid_keys
