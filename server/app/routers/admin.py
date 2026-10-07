"""Admin router for operational endpoints (requires an ``admin`` key)."""

import logging

from fastapi import APIRouter, Request

from ..audit import audit
from ..dependencies import AdminAccess, reload_mattstash
from ..rate_limit import limiter
from ..security.api_keys import invalidate_api_key_cache

logger = logging.getLogger("mattstash.api")
router = APIRouter()


@router.post("/admin/reload")
@limiter.limit("10/minute")
def force_reload(request: Request, principal: AdminAccess) -> dict[str, str]:
    """
    Force the server to reload the KeePass database from disk.

    Useful after external modifications (e.g., via the CLI).
    """
    success = reload_mattstash()
    audit(request, "admin-reload", success=success)

    if success:
        logger.info("Database reloaded via admin endpoint")
        return {"status": "reloaded"}
    logger.warning("Database reload requested but it failed or there is no instance to reload")
    return {"status": "no_change"}


@router.post("/admin/invalidate-api-key-cache")
@limiter.limit("10/minute")
def invalidate_keys(request: Request, principal: AdminAccess) -> dict[str, str]:
    """Force API keys to be re-read from their configured source."""
    invalidate_api_key_cache()
    audit(request, "admin-invalidate-keys")
    logger.info("API key cache invalidated via admin endpoint")
    return {"status": "api_key_cache_invalidated"}
