"""Admin router: operational endpoints and the management of principals, tokens and grants.

Everything here requires an admin principal (``authz.can_admin``: the admin flag, not disabled, and a kind that may
administer). The wire format is fixed by the admin API contract the CLI is built against.

Mutations edit the policy file under the library's lock (``edit_policy``: re-read from disk, validate, lockout check,
atomic write) and then reload the active state at once. Plaintext tokens exist only in the ``201`` response that
creates them; they are never logged or stored. All handlers are plain ``def`` (file locks and I/O run in the
threadpool).
"""

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from mattstash.authz import (
    Grant,
    PolicyEditor,
    PolicyError,
    Principal,
    Token,
    edit_policy,
    evaluate,
    is_valid_token_id,
    parse_duration,
    parse_duration_or_time,
    read_records,
)
from mattstash.authz.accesslog import printable
from mattstash.authz.models import utcnow
from mattstash.authz.store import MIN_IMPORT_KEY_LENGTH_FLOOR
from mattstash.utils.exceptions import DatabaseLockError, DatabaseLockTimeoutError

from ..config import config
from ..dependencies import reload_mattstash, require_admin
from ..models.requests import (
    CheckRequest,
    CreateGrantRequest,
    CreatePrincipalRequest,
    ImportTokenRequest,
    IssueTokenRequest,
    RotateTokenRequest,
    UpdatePrincipalRequest,
)
from ..rate_limit import limiter
from ..security.api_keys import AuthState, build_auth_state, get_auth_state, reload_key_policy_now

logger = logging.getLogger("mattstash.api")
router = APIRouter()

_READ_LIMIT = "60/minute"
_WRITE_LIMIT = "30/minute"
_READ_ONLY = "Policy file is read-only; edit it and POST /admin/invalidate-api-key-cache"
_NOT_ACTIVE = (
    "Saved to the policy file but NOT active: the server could not reload its key sources (see the server log). "
    "The previous policy is still in force."
)


# ---------------------------------------------------------------------------
# operational endpoints
# ---------------------------------------------------------------------------


@router.post("/admin/reload", dependencies=[Depends(require_admin("admin.reload"))])
@limiter.limit("10/minute")
def force_reload(request: Request) -> dict[str, str]:
    """
    Force the server to reload the KeePass database from disk.

    Useful after external modifications (e.g., via the CLI).
    """
    success = reload_mattstash()

    if success:
        logger.info("Database reloaded via admin endpoint")
        return {"status": "reloaded"}
    logger.warning("Database reload requested but it failed or there is no instance to reload")
    # Not a 200: a caller that has just replaced the database file must be able to tell that the server is still
    # serving the previous state (or nothing).
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=(
            "Database reload failed; the server serves nothing until the database file opens again "
            "(see the server log). Restoring a valid file recovers it without a restart."
        ),
    )


@router.post(
    "/admin/invalidate-api-key-cache",
    dependencies=[Depends(require_admin("admin.invalidate-api-key-cache"))],
)
@limiter.limit("10/minute")
def invalidate_keys(request: Request) -> dict[str, str | int]:
    """Re-read the API keys and the policy file now and make the result the active policy.

    Answers ``409`` if the sources cannot be loaded (bad edit, unreadable file): the PREVIOUS keys are then
    still active, so a key you meant to revoke may still work. Treat anything but 200 as "not revoked yet".
    """
    try:
        state = reload_key_policy_now()
    except Exception as exc:
        logger.error("API key reload failed: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="API key reload failed; the previous keys are still active (see the server log)",
        ) from None
    logger.info("API key policy reloaded via admin endpoint (%d keys)", state.credential_count)
    return {"status": "api_key_cache_invalidated", "keys": state.credential_count}


# ---------------------------------------------------------------------------
# serialisation
# ---------------------------------------------------------------------------


def _time(value: Optional[datetime]) -> Optional[str]:
    """RFC3339 UTC with a ``Z``, the form the policy file uses."""
    if value is None:
        return None
    utc = value.astimezone(UTC)
    return utc.isoformat(timespec="seconds" if utc.microsecond == 0 else "microseconds").removesuffix("+00:00") + "Z"


def _token_out(token: Token, now: datetime) -> dict[str, Any]:
    return {
        "id": token.id,
        "created": _time(token.created),
        "expires": _time(token.expires),
        "description": token.description,
        "expired": token.is_expired(now),
    }  # never the hash


def _principal_out(principal: Principal, now: datetime) -> dict[str, Any]:
    return {
        "name": principal.name,
        "kind": principal.kind,
        "description": principal.description,
        "admin": principal.admin,
        "disabled": principal.disabled,
        "created": _time(principal.created),
        "tokens": [_token_out(token, now) for token in principal.tokens],
    }


def _grant_out(grant: Grant, now: datetime) -> dict[str, Any]:
    return {
        "id": grant.id,
        "principal": grant.principal,
        "key": grant.key,
        "tag": grant.tag,
        "actions": sorted(grant.actions),
        "expires": _time(grant.expires),
        "description": grant.description,
        "created": _time(grant.created),
        "expired": grant.is_expired(now),
    }


def _not_found(what: str, ident: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{what} not found: {printable(ident)}")


def _bad_request(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=printable(detail))


def _conflict(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=printable(detail))


def _token_id_or_404(token_id: str) -> None:
    """A token id has a fixed shape. Anything else (a full token pasted by mistake, say) is answered with a fixed
    text that does not repeat it."""
    if not is_valid_token_id(token_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")


def _principal_or_404(state: AuthState, name: str) -> Principal:
    found = state.policy.principal(name)
    if found is None:
        raise _not_found("Principal", name)
    return found


# ---------------------------------------------------------------------------
# editing
# ---------------------------------------------------------------------------


@contextmanager
def _editing(request: Request, *, reduces: bool = False) -> Iterator[PolicyEditor]:
    """Edit the policy file and reload the active policy on success; map the library's failures to HTTP errors.

    ``reduces`` marks a change that takes access away (revoking a token, disabling or removing a
    principal, dropping the admin flag, removing a grant). If the saved file cannot be activated, such a change is
    answered ``409``: the caller must not believe the access is gone while the old policy still allows it. Any other
    change is answered normally but flagged (:func:`_reply`), since it does no harm that it is not active yet.
    """
    assert config.POLICY_FILE, "the server does not start without MATTSTASH_POLICY_FILE"
    try:
        with edit_policy(config.POLICY_FILE) as editor:
            yield editor
            # Check-then-save: build the state the server would run on from the EDITED policy, exactly as the loader
            # does, before the editor saves. A change the server could not load is refused and nothing is written.
            try:
                build_auth_state(editor.policy, None)
            except ValueError as exc:
                raise _conflict(f"The change would leave a policy the server cannot load: {exc}") from None
    except PolicyError as exc:
        raise _bad_request(str(exc)) from None  # safe by construction: never a token or a hash
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Policy file not found (MATTSTASH_POLICY_FILE)"
        ) from None
    except DatabaseLockTimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable",
            headers={"Retry-After": "2"},
        ) from None
    except DatabaseLockError as exc:  # the lock cannot be taken at all (read-only or unsupported filesystem)
        logger.error("Policy file cannot be locked: %s", type(exc).__name__)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=_READ_ONLY) from None
    except OSError as exc:  # read-only mount (Kubernetes ConfigMap/Secret), full disk, permissions
        logger.error("Policy file cannot be written: %s", type(exc).__name__)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=_READ_ONLY) from None
    if _activate():
        return
    if reduces:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=_NOT_ACTIVE)
    request.scope.setdefault("state", {})["policy_active"] = False


def _activate() -> bool:
    """Make the saved file the active policy now. False if that failed (a race with another writer, an I/O error): the
    change IS saved, and the caller decides how to tell the admin. The check before saving makes that rare."""
    try:
        reload_key_policy_now()
    except Exception as exc:
        logger.error("Policy saved but the reload failed: %s", type(exc).__name__)
        return False
    return True


def _reply(
    request: Request, payload: dict[str, Any], code: int = status.HTTP_200_OK, *, secret: bool = False
) -> JSONResponse:
    """The JSON answer of a mutation. If the change was saved but could not be activated, the body carries a
    ``warning`` and the response ``X-Policy-Active: false``. ``secret``: the body holds a plaintext token."""
    headers = {"Cache-Control": "no-store"} if secret else {}
    if request.scope.get("state", {}).get("policy_active") is False:
        payload = {**payload, "warning": _NOT_ACTIVE}
        headers["X-Policy-Active"] = "false"
    return JSONResponse(payload, status_code=code, headers=headers)


def _file_principal(editor: PolicyEditor, name: str) -> Principal:
    """The principal in the file as it is now on disk (404 if absent)."""
    found = editor.policy.principal(name)
    if found is None:
        raise _not_found("Principal", name)
    return found


def _expiry(text: Optional[str], now: datetime) -> Optional[datetime]:
    try:
        return parse_duration_or_time(text, now) if text is not None else None
    except PolicyError as exc:
        raise _bad_request(str(exc)) from None


def _grace(text: Optional[str], now: datetime) -> timedelta:
    """How long a rotated token keeps working: a RELATIVE duration (24h) only, never a date."""
    if not text:
        return timedelta(0)
    try:
        grace = parse_duration(text)
        now + grace
    except PolicyError as exc:
        raise _bad_request(str(exc)) from None
    except OverflowError:
        raise _bad_request("the grace period is outside the range of supported dates") from None
    return grace


def _since(text: str) -> datetime:
    """``24h`` means 24 hours ago; anything else is an absolute date or time."""
    now = utcnow()
    try:
        return now - parse_duration(text)
    except PolicyError:
        pass  # not a duration: an absolute time
    except OverflowError:
        raise _bad_request(f"{printable(text)!r} is outside the range of supported dates") from None
    try:
        return parse_duration_or_time(text, now)
    except PolicyError as exc:
        raise _bad_request(str(exc)) from None


# ---------------------------------------------------------------------------
# principals
# ---------------------------------------------------------------------------


@router.get("/admin/principals", dependencies=[Depends(require_admin("admin.principal.list"))])
@limiter.limit(_READ_LIMIT)
def list_principals(request: Request) -> dict[str, Any]:
    now = utcnow()
    return {"principals": [_principal_out(p, now) for p in get_auth_state().policy.principals]}


@router.post(
    "/admin/principals",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin("admin.principal.add"))],
)
@limiter.limit(_WRITE_LIMIT)
def create_principal(request: Request, body: CreatePrincipalRequest) -> JSONResponse:
    with _editing(request) as editor:
        principal = editor.add_principal(body.name, body.kind, body.description, body.admin)
        created = _principal_out(principal, editor.now)
    return _reply(request, created, status.HTTP_201_CREATED)


@router.get("/admin/principals/{name}", dependencies=[Depends(require_admin("admin.principal.show"))])
@limiter.limit(_READ_LIMIT)
def show_principal(request: Request, name: str) -> dict[str, Any]:
    state = get_auth_state()
    principal = _principal_or_404(state, name)
    now = utcnow()
    out = _principal_out(principal, now)
    out["grants"] = [_grant_out(g, now) for g in state.policy.grants_for(principal.name)]
    return out


@router.patch("/admin/principals/{name}", dependencies=[Depends(require_admin("admin.principal.update"))])
@limiter.limit(_WRITE_LIMIT)
def update_principal(request: Request, name: str, body: UpdatePrincipalRequest) -> JSONResponse:
    # disabling a principal or dropping its admin flag takes access away
    with _editing(request, reduces=body.disabled is True or body.admin is False) as editor:
        principal = _file_principal(editor, name)
        if body.disabled is not None:
            editor.set_disabled(principal.name, body.disabled)
        if body.admin is not None:
            editor.set_admin(principal.name, body.admin)
        if body.description is not None:
            editor.set_description(principal.name, body.description)
        updated = _principal_out(editor.policy.principal(principal.name) or principal, editor.now)
    return _reply(request, updated)


@router.delete("/admin/principals/{name}", dependencies=[Depends(require_admin("admin.principal.remove"))])
@limiter.limit(_WRITE_LIMIT)
def remove_principal(request: Request, name: str) -> JSONResponse:
    with _editing(request, reduces=True) as editor:
        principal = _file_principal(editor, name)
        removed = editor.remove_principal(principal.name)
    return _reply(request, {"detail": f"Principal removed: {principal.name}", "grants_removed": removed})


# ---------------------------------------------------------------------------
# tokens
# ---------------------------------------------------------------------------


@router.get("/admin/principals/{name}/tokens", dependencies=[Depends(require_admin("admin.token.list"))])
@limiter.limit(_READ_LIMIT)
def list_tokens(request: Request, name: str) -> dict[str, Any]:
    principal = _principal_or_404(get_auth_state(), name)
    now = utcnow()
    return {"tokens": [_token_out(t, now) for t in principal.tokens]}


@router.post("/admin/principals/{name}/tokens", dependencies=[Depends(require_admin("admin.token.issue"))])
@limiter.limit(_WRITE_LIMIT)
def issue_token(
    request: Request, name: str, body: Annotated[IssueTokenRequest, Body(default_factory=IssueTokenRequest)]
) -> JSONResponse:
    with _editing(request) as editor:
        principal = _file_principal(editor, name)
        expires = _expiry(body.expires, editor.now)
        token, plaintext = editor.issue_token(principal.name, expires, body.description)
    # The plaintext token is in this body and nowhere else: not stored, not logged, not cacheable.
    return _reply(
        request,
        {"token": plaintext, "id": token.id, "expires": _time(token.expires)},
        status.HTTP_201_CREATED,
        secret=True,
    )


@router.post("/admin/principals/{name}/tokens/import", dependencies=[Depends(require_admin("admin.token.import"))])
@limiter.limit(_WRITE_LIMIT)
def import_token(request: Request, name: str, body: ImportTokenRequest) -> JSONResponse:
    """Store an existing plain key as a token (zero-downtime migration off the removed v1 key sources).

    The key is in the request body and nowhere else: it is not echoed, not logged (the access line holds the route
    and the principal, never the body) and not part of any error text.
    """
    minimum = max(config.MIN_KEY_LENGTH, MIN_IMPORT_KEY_LENGTH_FLOOR) if body.min_length is None else body.min_length
    with _editing(request) as editor:
        principal = _file_principal(editor, name)
        expires = _expiry(body.expires, editor.now)
        token = editor.import_token(principal.name, body.key, minimum, expires, body.description)
    return _reply(request, {"id": token.id, "expires": _time(token.expires)}, status.HTTP_201_CREATED)


@router.delete(
    "/admin/principals/{name}/tokens/{token_id}", dependencies=[Depends(require_admin("admin.token.revoke"))]
)
@limiter.limit(_WRITE_LIMIT)
def revoke_token(request: Request, name: str, token_id: str) -> JSONResponse:
    _token_id_or_404(token_id)
    with _editing(request, reduces=True) as editor:
        principal = _file_principal(editor, name)
        if all(t.id != token_id for t in principal.tokens):
            raise _not_found("Token", token_id)
        editor.revoke_token(principal.name, token_id)
    return _reply(request, {"detail": f"Token revoked: {token_id}"})


@router.post(
    "/admin/principals/{name}/tokens/{token_id}/rotate", dependencies=[Depends(require_admin("admin.token.rotate"))]
)
@limiter.limit(_WRITE_LIMIT)
def rotate_token(
    request: Request,
    name: str,
    token_id: str,
    body: Annotated[RotateTokenRequest, Body(default_factory=RotateTokenRequest)],
) -> JSONResponse:
    _token_id_or_404(token_id)
    # Not ``reduces``: the new token is shown only in this answer, so a 409 would lose it. A rotation that is saved but
    # not active is answered 201 with the warning instead; the old token then keeps working until the reload succeeds.
    with _editing(request) as editor:
        principal = _file_principal(editor, name)
        if all(t.id != token_id for t in principal.tokens):
            raise _not_found("Token", token_id)
        grace = _grace(body.grace, editor.now)
        expires = _expiry(body.expires, editor.now)
        token, plaintext = editor.rotate_token(principal.name, token_id, grace, expires, body.description)
        after = editor.policy.principal(principal.name)
        old = next((t for t in after.tokens if t.id == token_id), None) if after is not None else None
    return _reply(
        request,
        {
            "token": plaintext,
            "id": token.id,
            "expires": _time(token.expires),
            "old_token_expires": _time(old.expires) if old is not None else None,
        },
        status.HTTP_201_CREATED,
        secret=True,
    )


# ---------------------------------------------------------------------------
# grants
# ---------------------------------------------------------------------------


@router.get("/admin/grants", dependencies=[Depends(require_admin("admin.grant.list"))])
@limiter.limit(_READ_LIMIT)
def list_grants(request: Request, principal: Annotated[str | None, Query(max_length=64)] = None) -> dict[str, Any]:
    state = get_auth_state()
    now = utcnow()
    grants = state.policy.grants
    if principal:  # an empty value is "not given", as everywhere
        grants = state.policy.grants_for(_principal_or_404(state, principal).name)
    return {"grants": [_grant_out(g, now) for g in grants]}


@router.post(
    "/admin/grants", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin("admin.grant.add"))]
)
@limiter.limit(_WRITE_LIMIT)
def create_grant(request: Request, body: CreateGrantRequest) -> JSONResponse:
    with _editing(request) as editor:
        principal = _file_principal(editor, body.principal)
        grant = editor.add_grant(
            principal.name,
            body.key,
            body.tag,
            body.actions if body.actions is not None else ("list", "read"),
            _expiry(body.expires, editor.now),
            body.description,
        )
        created = _grant_out(grant, editor.now)
    return _reply(request, created, status.HTTP_201_CREATED)


@router.delete("/admin/grants/{grant_id}", dependencies=[Depends(require_admin("admin.grant.remove"))])
@limiter.limit(_WRITE_LIMIT)
def remove_grant(request: Request, grant_id: str) -> JSONResponse:
    with _editing(request, reduces=True) as editor:
        if all(g.id != grant_id for g in editor.policy.grants):
            raise _not_found("Grant", grant_id)
        editor.remove_grant(grant_id)
    return _reply(request, {"detail": f"Grant removed: {grant_id}"})


# ---------------------------------------------------------------------------
# check and access log
# ---------------------------------------------------------------------------


@router.post("/admin/check", dependencies=[Depends(require_admin("admin.check"))])
@limiter.limit(_READ_LIMIT)
def check_access(request: Request, body: CheckRequest) -> dict[str, Any]:
    """Explain a decision: may this principal do this to this name (with these tags)?"""
    state = get_auth_state()
    principal = _principal_or_404(state, body.principal)
    try:
        decision = evaluate(state.policy, principal, body.action, body.name, body.tags)
    except PolicyError as exc:
        raise _bad_request(str(exc)) from None
    return {"allowed": decision.allowed, "reason": decision.reason, "grant": decision.grant_id}


@router.get("/admin/access-log", dependencies=[Depends(require_admin("admin.access-log"))])
@limiter.limit(_READ_LIMIT)
def read_access_log(
    request: Request,
    principal: Annotated[str | None, Query(max_length=64)] = None,
    decision: Annotated[str | None, Query(pattern="^(allowed|denied)?$")] = None,
    since: Annotated[str | None, Query(max_length=64, description="Duration ago (24h) or a date/time")] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> dict[str, Any]:
    if not config.ACCESS_LOG_FILE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No access log file configured (MATTSTASH_ACCESS_LOG_FILE)",
        )
    cutoff: Optional[datetime] = None
    if since:  # an empty value is "not given", like an empty principal or decision
        cutoff = _since(since)
    records = read_records(
        config.ACCESS_LOG_FILE, principal=principal or None, decision=decision or None, since=cutoff, limit=limit
    )
    return {"records": records, "count": len(records)}
