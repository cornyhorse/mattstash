"""Admin router for operational endpoints."""
import logging

from fastapi import APIRouter, Request

from ..dependencies import APIKeyDep, reload_mattstash
from ..rate_limit import limiter

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
