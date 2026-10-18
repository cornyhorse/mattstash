"""Admin router: operational endpoints and the management of principals, tokens and grants.

Everything here requires an admin principal (``authz.can_admin``: the admin flag, not disabled, and a kind that may
administer). The wire format is fixed by the admin API contract the CLI is built against.

Mutations edit the policy file under the library's lock (``edit_policy``: re-read from disk, validate, lockout check,
atomic write) and then reload the active state at once. Plaintext tokens exist only in the ``201`` response that
creates them; they are never logged or stored. All handlers are plain ``def`` (file locks and I/O run in the
threadpool).
"""

import logging
import re
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from mattstash.authz import (
    LEGACY_KIND,
    Grant,
    PolicyEditor,
    PolicyError,
    Principal,
    Token,
    edit_policy,
    evaluate,
    parse_duration_or_time,
    read_records,
)
from mattstash.authz.accesslog import printable
from mattstash.authz.models import utcnow
from mattstash.utils.exceptions import DatabaseLockError

from ..accesslog import note
from ..config import config
from ..dependencies import reload_mattstash, require_admin
from ..models.requests import (
    CheckRequest,
    CreateGrantRequest,
    CreatePrincipalRequest,
    IssueTokenRequest,
    RotateTokenRequest,
    UpdatePrincipalRequest,
)
from ..rate_limit import limiter
from ..security.api_keys import AuthState, get_auth_state, reload_key_policy_now

logger = logging.getLogger("mattstash.api")
router = APIRouter()

_READ_LIMIT = "60/minute"
_WRITE_LIMIT = "30/minute"
_DURATION = re.compile(r"\s*\d{1,6}[mhdw]\s*", re.ASCII)
_READ_ONLY = "Policy file is read-only; edit it and POST /admin/invalidate-api-key-cache"


# ---------------------------------------------------------------------------
# operational endpoints
# ---------------------------------------------------------------------------


@router.post("/admin/reload", dependencies=[Depends(require_admin("admin.reload", scoped_legacy_ok=True))])
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
    dependencies=[Depends(require_admin("admin.invalidate-api-key-cache", scoped_legacy_ok=True))],
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
        "legacy": principal.kind == LEGACY_KIND,
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
        "legacy": grant.id.startswith("legacy:"),
    }


def _not_found(what: str, ident: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{what} not found: {printable(ident)}")


def _bad_request(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=printable(detail))


def _legacy_refusal() -> HTTPException:
    return _bad_request("Legacy keys are configured through MATTSTASH_API_KEY / MATTSTASH_API_KEYS_FILE, not here")


def _principal_or_404(state: AuthState, name: str) -> Principal:
    found = state.policy.principal(name)
    if found is None:
        raise _not_found("Principal", name)
    return found


# ---------------------------------------------------------------------------
# editing
# ---------------------------------------------------------------------------


@contextmanager
def _editing() -> Iterator[PolicyEditor]:
    """Edit the policy file and reload the active policy on success; map the library's failures to HTTP errors."""
    if not config.POLICY_FILE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="No policy file configured (MATTSTASH_POLICY_FILE)"
        )
    try:
        with edit_policy(config.POLICY_FILE, legacy_admin_available=get_auth_state().legacy_admin) as editor:
            yield editor
    except PolicyError as exc:
        raise _bad_request(str(exc)) from None  # safe by construction: never a token or a hash
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Policy file not found (MATTSTASH_POLICY_FILE)"
        ) from None
    except DatabaseLockError as exc:
        if str(exc).startswith("Timed out"):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service temporarily unavailable",
                headers={"Retry-After": "2"},
            ) from None
        logger.error("Policy file cannot be locked: %s", type(exc).__name__)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=_READ_ONLY) from None
    except OSError as exc:  # read-only mount (Kubernetes ConfigMap/Secret), full disk, permissions
        logger.error("Policy file cannot be written: %s", type(exc).__name__)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=_READ_ONLY) from None
    _activate()


def _activate() -> None:
    """Make the saved file the active policy now. The change IS saved even if this fails (e.g. a broken legacy
    source), so the response is not turned into an error: it may carry a token that is shown only once."""
    try:
        reload_key_policy_now()
    except Exception as exc:
        logger.error("Policy saved but the reload failed: %s", type(exc).__name__)


def _file_principal(editor: PolicyEditor, name: str) -> Principal:
    """The principal in the file as it is now on disk (404 if absent; legacy principals live outside the file)."""
    found = editor.policy.principal(name)
    if found is None:
        if name.casefold().startswith("legacy-") or (
            (current := get_auth_state().policy.principal(name)) is not None and current.kind == LEGACY_KIND
        ):
            raise _legacy_refusal()
        raise _not_found("Principal", name)
    return found


def _expiry(text: Optional[str], now: datetime) -> Optional[datetime]:
    try:
        return parse_duration_or_time(text, now) if text else None
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
def create_principal(request: Request, body: CreatePrincipalRequest) -> dict[str, Any]:
    note(request, key=body.name)
    with _editing() as editor:
        principal = editor.add_principal(body.name, body.kind, body.description, body.admin)
        created = _principal_out(principal, editor.now)
    return created


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
def update_principal(request: Request, name: str, body: UpdatePrincipalRequest) -> dict[str, Any]:
    with _editing() as editor:
        principal = _file_principal(editor, name)
        if body.disabled is not None:
            editor.set_disabled(principal.name, body.disabled)
        if body.admin is not None:
            editor.set_admin(principal.name, body.admin)
        if body.description is not None:
            editor.set_description(principal.name, body.description)
        updated = _principal_out(editor.policy.principal(principal.name) or principal, editor.now)
    return updated


@router.delete("/admin/principals/{name}", dependencies=[Depends(require_admin("admin.principal.remove"))])
@limiter.limit(_WRITE_LIMIT)
def remove_principal(request: Request, name: str) -> dict[str, Any]:
    with _editing() as editor:
        principal = _file_principal(editor, name)
        removed = editor.remove_principal(principal.name)
    return {"detail": f"Principal removed: {principal.name}", "grants_removed": removed}


# ---------------------------------------------------------------------------
# tokens
# ---------------------------------------------------------------------------


@router.get("/admin/principals/{name}/tokens", dependencies=[Depends(require_admin("admin.token.list"))])
@limiter.limit(_READ_LIMIT)
def list_tokens(request: Request, name: str) -> dict[str, Any]:
    principal = _principal_or_404(get_auth_state(), name)
    now = utcnow()
    return {"tokens": [_token_out(t, now) for t in principal.tokens]}


def _token_response(payload: dict[str, Any]) -> JSONResponse:
    # The plaintext token is in this body and nowhere else: not stored, not logged, not cacheable.
    return JSONResponse(payload, status_code=status.HTTP_201_CREATED, headers={"Cache-Control": "no-store"})


@router.post("/admin/principals/{name}/tokens", dependencies=[Depends(require_admin("admin.token.issue"))])
@limiter.limit(_WRITE_LIMIT)
def issue_token(request: Request, name: str, body: IssueTokenRequest) -> JSONResponse:
    with _editing() as editor:
        principal = _file_principal(editor, name)
        expires = _expiry(body.expires, editor.now)
        token, plaintext = editor.issue_token(principal.name, expires, body.description)
    return _token_response({"token": plaintext, "id": token.id, "expires": _time(token.expires)})


@router.delete(
    "/admin/principals/{name}/tokens/{token_id}", dependencies=[Depends(require_admin("admin.token.revoke"))]
)
@limiter.limit(_WRITE_LIMIT)
def revoke_token(request: Request, name: str, token_id: str) -> dict[str, str]:
    with _editing() as editor:
        principal = _file_principal(editor, name)
        if all(t.id != token_id for t in principal.tokens):
            raise _not_found("Token", token_id)
        editor.revoke_token(principal.name, token_id)
    return {"detail": f"Token revoked: {token_id}"}


@router.post(
    "/admin/principals/{name}/tokens/{token_id}/rotate", dependencies=[Depends(require_admin("admin.token.rotate"))]
)
@limiter.limit(_WRITE_LIMIT)
def rotate_token(request: Request, name: str, token_id: str, body: RotateTokenRequest) -> JSONResponse:
    with _editing() as editor:
        principal = _file_principal(editor, name)
        if all(t.id != token_id for t in principal.tokens):
            raise _not_found("Token", token_id)
        grace = timedelta(0)
        if body.grace:
            grace = _expiry(body.grace, editor.now) - editor.now  # type: ignore[operator]
        expires = _expiry(body.expires, editor.now)
        token, plaintext = editor.rotate_token(principal.name, token_id, grace, expires, body.description)
        after = editor.policy.principal(principal.name)
        old = next((t for t in after.tokens if t.id == token_id), None) if after is not None else None
    return _token_response(
        {
            "token": plaintext,
            "id": token.id,
            "expires": _time(token.expires),
            "old_token_expires": _time(old.expires) if old is not None else None,
        }
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
    if principal:
        grants = state.policy.grants_for(_principal_or_404(state, principal).name)
    return {"grants": [_grant_out(g, now) for g in grants]}


@router.post(
    "/admin/grants", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin("admin.grant.add"))]
)
@limiter.limit(_WRITE_LIMIT)
def create_grant(request: Request, body: CreateGrantRequest) -> dict[str, Any]:
    note(request, key=body.principal)
    with _editing() as editor:
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
    return created


@router.delete("/admin/grants/{grant_id}", dependencies=[Depends(require_admin("admin.grant.remove"))])
@limiter.limit(_WRITE_LIMIT)
def remove_grant(request: Request, grant_id: str) -> dict[str, str]:
    with _editing() as editor:
        if all(g.id != grant_id for g in editor.policy.grants):
            if grant_id.startswith("legacy:"):
                raise _legacy_refusal()
            raise _not_found("Grant", grant_id)
        editor.remove_grant(grant_id)
    return {"detail": f"Grant removed: {grant_id}"}


# ---------------------------------------------------------------------------
# check and access log
# ---------------------------------------------------------------------------


@router.post("/admin/check", dependencies=[Depends(require_admin("admin.check"))])
@limiter.limit(_READ_LIMIT)
def check_access(request: Request, body: CheckRequest) -> dict[str, Any]:
    """Explain a decision: may this principal do this to this name (with these tags)?"""
    note(request, key=body.principal)
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
    decision: Literal["allowed", "denied"] | None = None,
    since: Annotated[str | None, Query(max_length=64, description="Duration ago (24h) or a date/time")] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> dict[str, Any]:
    if not config.ACCESS_LOG_FILE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No access log file configured (MATTSTASH_ACCESS_LOG_FILE)",
        )
    cutoff: Optional[datetime] = None
    if since:
        now = utcnow()
        cutoff = _expiry(since, now)
        if _DURATION.fullmatch(since) and cutoff is not None:
            cutoff = now - (cutoff - now)  # "24h" means 24 hours ago
    records = read_records(config.ACCESS_LOG_FILE, principal=principal, decision=decision, since=cutoff, limit=limit)
    return {"records": records, "count": len(records)}
