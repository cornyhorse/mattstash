"""Admin router for operational endpoints (requires an ``admin`` key)."""

import logging

from fastapi import APIRouter, HTTPException, Request, status

from ..audit import audit
from ..dependencies import AdminAccess, reload_mattstash
from ..rate_limit import limiter
from ..security.api_keys import reload_key_policy_now

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
def invalidate_keys(request: Request, principal: AdminAccess) -> dict[str, str | int]:
    """Re-read the API keys now and make them the active policy.

    Answers ``409`` if the key source cannot be loaded (bad edit, unreadable file): the PREVIOUS keys are then
    still active, so a key you meant to revoke may still work. Treat anything but 200 as "not revoked yet".
    """
    try:
        policy = reload_key_policy_now()
    except Exception as exc:
        logger.error("API key reload failed: %s", type(exc).__name__)
        audit(request, "admin-invalidate-keys", success=False)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="API key reload failed; the previous keys are still active (see the server log)",
        ) from None
    audit(request, "admin-invalidate-keys", success=True, keys=len(policy))
    logger.info("API key policy reloaded via admin endpoint (%d keys)", len(policy))
    return {"status": "api_key_cache_invalidated", "keys": len(policy)}
