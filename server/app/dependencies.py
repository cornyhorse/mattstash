"""Dependency injection for FastAPI endpoints."""

import logging
import threading
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from mattstash import MattStash

from .config import config
from .security.api_keys import Principal, authenticate

logger = logging.getLogger("mattstash.api")

# Cached MattStash instance (MattStash itself is thread-safe; this lock only guards creation)
_mattstash_instance: MattStash | None = None
_mattstash_lock = threading.Lock()


def initialize_mattstash() -> MattStash:
    """Open the database (creating the singleton). Raises the library's typed errors on failure."""
    global _mattstash_instance

    with _mattstash_lock:
        if _mattstash_instance is None:
            instance = MattStash(path=config.DB_PATH, password=config.get_kdbx_password())
            instance._ensure_initialized()  # open now: wrong password / missing DB fail here
            _mattstash_instance = instance
        return _mattstash_instance


def get_mattstash() -> MattStash:
    """Get the MattStash instance (opened lazily if startup has not done so yet)."""
    if _mattstash_instance is not None:
        return _mattstash_instance
    try:
        return initialize_mattstash()
    except Exception as exc:
        logger.error("Failed to initialize MattStash: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable",
            headers={"Retry-After": "5"},
        ) from None


def reload_mattstash() -> bool:
    """Force the singleton MattStash instance to reload from disk.

    Returns:
        True if reload was successful, False otherwise.
    """
    with _mattstash_lock:
        if _mattstash_instance is None:
            return False
        return _mattstash_instance.reload()


def reload_mattstash_if_changed() -> bool:
    """Check for external KDBX modifications and reload if detected.

    Returns:
        True if a reload was performed, False otherwise.
    """
    with _mattstash_lock:
        if _mattstash_instance is None:
            return False
        return _mattstash_instance.reload_if_changed()


async def authenticate_request(
    request: Request,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> Principal:
    """Authenticate the X-API-Key header and record the principal for auditing."""
    try:
        principal = authenticate(x_api_key) if x_api_key else None
    except Exception as exc:  # key store unusable (e.g. unreadable file on first load): not the caller's fault
        logger.error("API key store unavailable: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Service temporarily unavailable"
        ) from None
    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")
    request.state.principal = principal
    return principal


def require(op: str) -> Callable[..., Principal]:
    """Dependency factory: the caller must be authenticated and allowed to perform ``op``."""

    async def dependency(principal: Annotated[Principal, Depends(authenticate_request)]) -> Principal:
        if not principal.can(op):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return principal

    return dependency


def require_writes_enabled() -> None:
    """Writes are off unless MATTSTASH_ALLOW_WRITES is set (read-only by default)."""
    if not config.ALLOW_WRITES:
        raise HTTPException(
            status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
            detail="This server is read-only. Set MATTSTASH_ALLOW_WRITES=true to enable writes.",
            headers={"Allow": "GET"},
        )


def ensure_name_in_scope(principal: Principal, name: str, *, hide: bool) -> None:
    """Raise unless ``principal`` may touch ``name``.

    ``hide=True`` (reads) answers 404 so a scoped key cannot probe which names exist outside its scope;
    ``hide=False`` (writes/deletes) answers 403, which reveals nothing because it is unconditional.
    """
    if not principal.allows_name(name):
        if hide:
            # must be byte-identical to the router's genuine "not found" response
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Credential not found: {name}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")


# Type aliases for dependency injection
MattStashDep = Annotated[MattStash, Depends(get_mattstash)]
ReadAccess = Annotated[Principal, Depends(require("read"))]
WriteAccess = Annotated[Principal, Depends(require("write"))]
DeleteAccess = Annotated[Principal, Depends(require("delete"))]
AdminAccess = Annotated[Principal, Depends(require("admin"))]
WritesEnabled = Annotated[None, Depends(require_writes_enabled)]
