"""Admin router for operational endpoints."""
import logging

from fastapi import APIRouter, Request

from ..dependencies import APIKeyDep, reload_mattstash
from ..rate_limit import limiter
from ..security.api_keys import invalidate_api_key_cache

logger = logging.getLogger("mattstash.api")
router = APIRouter()


@router.post("/admin/reload")
@limiter.limit("10/minute")
async def force_reload(  # pragma: no cover
    request: Request,
    api_key: APIKeyDep,
) -> dict[str, str]:
    """
    Force the server to reload the KeePass database from disk.

    Useful after external modifications (e.g., via the CLI).
    """
    success = reload_mattstash()

    if success:
        logger.info("Database reloaded via admin endpoint")
        return {"status": "reloaded"}
    else:
        logger.warning("Database reload requested but no instance to reload")
        return {"status": "no_change"}


@router.post("/admin/invalidate-api-key-cache")
@limiter.limit("10/minute")
async def invalidate_keys(  # pragma: no cover
    request: Request,
    api_key: APIKeyDep,
) -> dict[str, str]:
    """Force API keys to be re-read from their configured source."""
    invalidate_api_key_cache()
    logger.info("API key cache invalidated via admin endpoint")
    return {"status": "api_key_cache_invalidated"}
