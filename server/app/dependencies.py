"""Dependency injection for FastAPI endpoints."""
import logging
import threading
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status

from mattstash import MattStash

from .config import config
from .security.api_keys import verify_api_key

logger = logging.getLogger("mattstash.api")

# Cached MattStash instance (thread-safe)
_mattstash_instance: MattStash | None = None
_mattstash_lock = threading.Lock()


def get_mattstash() -> MattStash:  # pragma: no cover
    """Get or create MattStash instance (thread-safe singleton)."""
    global _mattstash_instance
    
    if _mattstash_instance is None:
        with _mattstash_lock:
            if _mattstash_instance is None:
                try:
                    password = config.get_kdbx_password()
                    _mattstash_instance = MattStash(
                        db_path=config.DB_PATH,
                        password=password
                    )
                except Exception as e:
                    logger.error("Failed to initialize MattStash: %s", e)
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Service temporarily unavailable"
                    )
    
    return _mattstash_instance


async def verify_api_key_header(  # pragma: no cover
    x_api_key: Annotated[str | None, Header()] = None
) -> str:
    """Verify API key from header."""
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )
    
    if not verify_api_key(x_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )
    
    return x_api_key


# Type aliases for dependency injection
MattStashDep = Annotated[MattStash, Depends(get_mattstash)]
APIKeyDep = Annotated[str, Depends(verify_api_key_header)]
