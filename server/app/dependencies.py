"""Dependency injection for FastAPI endpoints."""

import logging
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Optional

from fastapi import Depends, Header, HTTPException, Request, status
from mattstash import MattStash
from mattstash.authz import LEGACY_KIND, Decision, Policy, Principal, admin_decision, evaluate
from mattstash.authz.models import utcnow

from .accesslog import note
from .config import config
from .errors import translate_errors
from .security.api_keys import AuthResult, authenticate

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


@dataclass(frozen=True)
class Caller:
    """The authenticated principal and the policy snapshot it was authenticated against."""

    principal: Principal
    policy: Policy
    token_id: Optional[str] = None
    unscoped: bool = False  # authenticated by a legacy key that always had full access (env / plain-list key)


async def authenticate_request(
    request: Request,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> Caller:
    """Return the authenticated caller.

    The security middleware has normally authenticated the request already (and throttled failures); its result
    is reused here. If the app is run without that middleware the header is verified here instead.
    """
    result: Optional[AuthResult] = request.scope.get("state", {}).get("auth")
    if result is None:
        try:
            result = authenticate(x_api_key)
        except Exception as exc:  # key store unusable (e.g. unreadable file on first load): not the caller's fault
            logger.error("API key store unavailable: %s", type(exc).__name__)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Service temporarily unavailable"
            ) from None
        request.state.auth = result
    if result.principal is None or result.policy is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")
    return Caller(result.principal, result.policy, result.token_id, result.unscoped)


def _forbidden() -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")


def _holds(caller: Caller, action: str) -> bool:
    """Whether any unexpired grant of the caller includes ``action`` (on any name)."""
    now = utcnow()
    return any(
        action in grant.actions and not grant.is_expired(now)
        for grant in caller.policy.grants_for(caller.principal.name)
    )


def require_grant_for(action: str, route: str) -> Callable[..., Caller]:
    """Dependency factory for write/delete: the caller must hold ``action`` on SOME name, else 403 at once.

    This keeps the old order for a principal that can never do it (403 before the read-only 405, and without taking a
    write slot). Whether it may touch THIS name is decided in the handler by :func:`authorize_name`.
    """

    async def dependency(request: Request, caller: Annotated[Caller, Depends(authenticate_request)]) -> Caller:
        if caller.principal.disabled or not _holds(caller, action):
            note(
                request,
                action=action,
                route=route,
                key=request.path_params.get("name"),
                decision="denied",
                reason="disabled" if caller.principal.disabled else "no-grant",
            )
            raise _forbidden()
        return caller

    return dependency


def require_admin(route: str, *, scoped_legacy_ok: bool = False) -> Callable[..., Caller]:
    """Dependency factory for ``/admin/*``: the caller must be an enabled admin of a kind that may administer.

    In v1 ``ops: ["admin"]`` meant only ``/admin/reload`` and ``/admin/invalidate-api-key-cache``. A legacy principal
    that came from a v1 JSON policy therefore passes only where ``scoped_legacy_ok`` is set (those two routes); the
    env key and plain-list keys always had full access and may use every admin endpoint.
    """

    async def dependency(request: Request, caller: Annotated[Caller, Depends(authenticate_request)]) -> Caller:
        decision = admin_decision(caller.principal)
        if decision.allowed and caller.principal.kind == LEGACY_KIND and not caller.unscoped and not scoped_legacy_ok:
            decision = Decision(False, "legacy-scoped")
        key = request.path_params.get("name") or request.path_params.get("grant_id")
        note(
            request,
            action="admin",
            route=route,
            key=key,
            decision="allowed" if decision.allowed else "denied",
            reason=None if decision.allowed else decision.reason,
        )
        if not decision.allowed:
            raise _forbidden()
        return caller

    return dependency


def require_writes_enabled() -> None:
    """Writes are off unless MATTSTASH_ALLOW_WRITES is set (read-only by default)."""
    if not config.ALLOW_WRITES:
        raise HTTPException(
            status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
            detail="This server is read-only. Set MATTSTASH_ALLOW_WRITES=true to enable writes.",
            headers={"Allow": "GET"},
        )


def _latest_tags(mattstash: MattStash, name: str) -> list[str]:
    """The tags of the latest version of ``name``.

    ``get()`` cannot be used: it returns a bare dict, without tags, for a password-only entry. Tags decide access to
    EVERY version, so re-tagging an old version never opens it up.
    """
    for credential in mattstash.list(show_password=False, latest_only=True):
        if credential.credential_name == name:
            return list(credential.tags)
    return []


def authorize_name(
    request: Request,
    caller: Caller,
    action: str,
    route: str,
    name: str,
    *,
    mattstash: Optional[MattStash] = None,
    not_found_detail: Optional[str] = None,
) -> None:
    """Raise unless ``caller`` may do ``action`` on ``name``; record the decision for the access log.

    Reads answer 404 with exactly ``not_found_detail`` (the endpoint's text for a missing name), so a caller cannot
    probe which names exist outside its grants. Writes and deletes answer 403, which reveals nothing because it is
    returned before the database is touched. A tag grant can allow ``read``, so when the name pattern does not match
    and the caller holds a tag grant, the tags of the latest version are consulted.
    """
    now = utcnow()
    decision = evaluate(caller.policy, caller.principal, action, name, now=now)
    if not decision.allowed and action == "read" and mattstash is not None and _has_tag_grant(caller, action, now):
        with translate_errors("authorize"):
            tags = _latest_tags(mattstash, name)
        decision = evaluate(caller.policy, caller.principal, action, name, tags, now=now)
    note(
        request,
        action=action,
        route=route,
        key=name,
        decision="allowed" if decision.allowed else "denied",
        reason=None if decision.allowed else decision.reason,
        grant=decision.grant_id,
    )
    if decision.allowed:
        return
    if action == "read":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=not_found_detail or f"Credential not found: {name}"
        )
    raise _forbidden()


def _has_tag_grant(caller: Caller, action: str, now: datetime) -> bool:
    return any(
        grant.tag is not None and action in grant.actions and not grant.is_expired(now)
        for grant in caller.policy.grants_for(caller.principal.name)
    )


# Type aliases for dependency injection
MattStashDep = Annotated[MattStash, Depends(get_mattstash)]
ReadAccess = Annotated[Caller, Depends(authenticate_request)]
WriteAccess = Annotated[Caller, Depends(require_grant_for("write", "put"))]
DeleteAccess = Annotated[Caller, Depends(require_grant_for("delete", "delete"))]
WritesEnabled = Annotated[None, Depends(require_writes_enabled)]


_writes_in_flight = 0
_writes_lock = threading.Lock()


def write_slot() -> Iterator[None]:
    """Admit at most ``MAX_CONCURRENT_WRITES`` writes at a time; the rest get 503 + ``Retry-After`` at once."""
    global _writes_in_flight
    with _writes_lock:
        busy = _writes_in_flight >= config.MAX_CONCURRENT_WRITES
        if not busy:
            _writes_in_flight += 1
    if busy:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Too many writes in progress; retry shortly",
            headers={"Retry-After": "1"},
        )
    try:
        yield
    finally:
        with _writes_lock:
            _writes_in_flight -= 1


WriteSlot = Annotated[None, Depends(write_slot)]
