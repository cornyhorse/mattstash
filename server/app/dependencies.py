"""Dependency injection for FastAPI endpoints."""
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status

from mattstash import MattStash

from .config import config
from .security.api_keys import verify_api_key


# Cached MattStash instance
_mattstash_instance: MattStash | None = None


def get_mattstash() -> MattStash:
    """Get or create MattStash instance (singleton)."""
    global _mattstash_instance
    
    if _mattstash_instance is None:
        try:
            password = config.get_kdbx_password()
            _mattstash_instance = MattStash(
                db_path=config.DB_PATH,
                password=password
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Failed to initialize MattStash: {str(e)}"
            )
    
    return _mattstash_instance


async def verify_api_key_header(
    x_api_key: Annotated[str | None, Header()] = None
) -> str:
    """Verify API key from header."""
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Provide X-API-Key header."
        )
    
    if not verify_api_key(x_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    return x_api_key


# Type aliases for dependency injection
MattStashDep = Annotated[MattStash, Depends(get_mattstash)]
APIKeyDep = Annotated[str, Depends(verify_api_key_header)]
