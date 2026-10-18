"""Credentials router for CRUD operations.

All handlers are plain ``def`` (not ``async def``): the KeePass work (decrypting, re-encrypting and
saving the database takes ~0.5 s) therefore runs in FastAPI's threadpool instead of blocking the
event loop, so health probes and other requests stay responsive while a write is in progress.
"""

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from mattstash.authz import visible
from mattstash.authz.models import utcnow
from mattstash.models.credential import Credential

from ..accesslog import note
from ..dependencies import (
    DeleteAccess,
    MattStashDep,
    ReadAccess,
    WriteAccess,
    WritesEnabled,
    WriteSlot,
    authorize_name,
)
from ..errors import translate_errors
from ..models.requests import CreateCredentialRequest
from ..models.responses import (
    CreateCredentialResponse,
    CredentialListResponse,
    CredentialResponse,
    SearchResponse,
    SearchResult,
    VersionListResponse,
)
from ..rate_limit import limiter, read_limit
from ..validation import MAX_NAME_LENGTH, is_valid_name, require_valid_name, require_valid_prefix

logger = logging.getLogger("mattstash.api")
router = APIRouter()

_MASK = "*****"


def _validate_credential_name(name: str) -> None:
    """Validate credential name (kept as a function for callers/tests)."""
    require_valid_name(name)


def _not_found(name: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Credential not found: {name}")


def _normalize_credential(
    name: str,
    result: Credential | dict[str, Any],
    show_password: bool = False,
) -> CredentialResponse:
    """Convert a Credential object or simple-secret dict to CredentialResponse.

    MattStash.get() returns either:
      - Credential dataclass (full credential)
      - dict with keys: name, version, value, notes (simple secret)
    """
    if isinstance(result, Credential):
        pwd = result.password
        return CredentialResponse(
            name=name,
            username=result.username,
            password=pwd if show_password else _MASK,
            url=result.url,
            notes=result.notes,
            version=result.version,
        )

    # Simple-secret dict
    value = result.get("value")
    return CredentialResponse(
        name=name,
        username=None,
        password=value if show_password else _MASK,
        url=None,
        notes=result.get("notes"),
        version=result.get("version"),
    )


# ---------------------------------------------------------------------------
# GET endpoints
# ---------------------------------------------------------------------------


@router.get("/credentials/{name}", response_model=CredentialResponse)
@limiter.limit(read_limit)
def get_credential(
    request: Request,
    name: str,
    mattstash: MattStashDep,
    caller: ReadAccess,
    version: int | None = Query(None, ge=0, description="Specific version to retrieve"),
    show_password: bool = Query(False, description="Show actual password instead of masking"),
) -> Response:
    """
    Get a specific credential by name.

    - **name**: Credential name
    - **version**: Optional version number
    - **show_password**: Whether to show the actual password (default: masked)
    """
    require_valid_name(name)
    authorize_name(request, caller, "read", "get", name, mattstash=mattstash)
    note(request, version=version)
    with translate_errors("get"):
        credential = mattstash.get(name, show_password=True, version=version)

    if credential is None:
        raise _not_found(name)

    if show_password:
        note(request, reveal=True)  # the value is in the response (a miss above reveals nothing)
    response_data = _normalize_credential(name, credential, show_password)
    return Response(
        content=response_data.model_dump_json(),
        media_type="application/json",
        headers={"Cache-Control": "no-store"},
    )


@router.get("/credentials", response_model=CredentialListResponse)
@limiter.limit(read_limit)
def list_credentials(
    request: Request,
    response: Response,
    mattstash: MattStashDep,
    caller: ReadAccess,
    prefix: str | None = Query(None, description="Filter by name prefix"),
    show_password: bool = Query(False, description="Show actual passwords instead of masking"),
) -> CredentialListResponse:
    """
    List credentials (latest version of each) that this principal may ``list``.

    - **prefix**: Optional prefix filter
    - **show_password**: Whether to show actual passwords (default: masked)

    Username, URL, notes and the value are filled in only for entries the principal may also ``read``; the others
    are returned with just name and version (password always masked).

    Entries whose titles contain characters outside ``[A-Za-z0-9_.-]`` are not addressable through this
    API and are not listed.
    """
    response.headers["Cache-Control"] = "no-store"
    if prefix:
        require_valid_prefix(prefix)
    with translate_errors("list"):
        all_creds = mattstash.list(show_password=True, latest_only=True)

    now = utcnow()
    candidates = [
        c
        for c in all_creds
        if is_valid_name(c.credential_name) and (not prefix or c.credential_name.startswith(prefix))
    ]
    pairs = [(c.credential_name, c.tags) for c in candidates]
    listed = set(visible(caller.policy, caller.principal, "list", pairs, now))
    shown = [c for c in candidates if c.credential_name in listed]
    readable = set(visible(caller.policy, caller.principal, "read", [(c.credential_name, c.tags) for c in shown], now))
    credentials = [
        _normalize_credential(c.credential_name, c, show_password)
        if c.credential_name in readable
        else CredentialResponse(name=c.credential_name, password=_MASK, version=c.version)
        for c in shown
    ]
    note(
        request,
        action="list",
        route="list",
        key=prefix or None,
        decision="allowed",
        count=len(credentials),
        reveal=True if show_password else None,
    )
    return CredentialListResponse(credentials=credentials, count=len(credentials))


@router.get("/search", response_model=SearchResponse)
@limiter.limit(read_limit)
def search_credentials(
    request: Request,
    response: Response,
    mattstash: MattStashDep,
    caller: ReadAccess,
    q: str | None = Query(None, max_length=MAX_NAME_LENGTH, description="Case-insensitive part of the name"),
    tag: str | None = Query(None, max_length=100, description="Exact tag of the latest version"),
) -> SearchResponse:
    """
    Find credentials by part of the name and/or by tag. Only names and tags are searched and returned (never notes
    or values), and only entries the principal may ``list`` appear. At least one of ``q`` and ``tag`` is required.
    """
    response.headers["Cache-Control"] = "no-store"
    q, tag = q or None, tag or None
    if q is None and tag is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Provide q, tag or both")
    with translate_errors("search"):
        all_creds = mattstash.list(show_password=False, latest_only=True)

    wanted = q.casefold() if q is not None else None
    matches = [
        c
        for c in all_creds
        if is_valid_name(c.credential_name)
        and (wanted is None or wanted in c.credential_name.casefold())
        and (tag is None or tag in c.tags)
    ]
    allowed = set(
        visible(caller.policy, caller.principal, "list", [(c.credential_name, c.tags) for c in matches], utcnow())
    )
    results = [SearchResult(name=c.credential_name, tags=list(c.tags)) for c in matches if c.credential_name in allowed]
    note(request, action="list", route="search", key=q, tag=tag, decision="allowed", count=len(results))
    return SearchResponse(results=results, count=len(results))


@router.get("/credentials/{name}/versions", response_model=VersionListResponse)
@limiter.limit(read_limit)
def list_versions(
    request: Request,
    name: str,
    mattstash: MattStashDep,
    caller: ReadAccess,
) -> VersionListResponse:
    """
    List all versions of a credential.

    - **name**: Credential name
    """
    require_valid_name(name)
    authorize_name(request, caller, "read", "versions", name, mattstash=mattstash)
    with translate_errors("versions"):
        versions = mattstash.list_versions(name)

    if not versions:
        raise _not_found(name)

    return VersionListResponse(
        name=name,
        versions=versions,
        latest=versions[-1],  # Last version is the latest
    )


# ---------------------------------------------------------------------------
# POST / DELETE endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/credentials/{name}",
    response_model=CreateCredentialResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit("30/minute")
def create_credential(
    request: Request,
    response: Response,
    name: str,
    body: CreateCredentialRequest,
    mattstash: MattStashDep,
    caller: WriteAccess,
    _writes: WritesEnabled,
    _slot: WriteSlot,
) -> CreateCredentialResponse:
    """
    Create a new version of a credential (or the first one).

    - **name**: Credential name
    """
    require_valid_name(name)
    authorize_name(request, caller, "write", "put", name)
    response.headers["Cache-Control"] = "no-store"
    with translate_errors("put"):
        result = mattstash.put(
            name,
            value=body.value,
            username=body.username,
            password=body.password,
            url=body.url,
            notes=body.notes,
            tags=body.tags,
        )

    if result is None:  # pragma: no cover - put() raises on failure
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to store credential")

    version = result.get("version") if isinstance(result, dict) else result.version
    return CreateCredentialResponse(
        name=name,
        version=version or "0000000001",
        created=version is None or int(version) == 1,
    )


@router.delete("/credentials/{name}", status_code=status.HTTP_200_OK)
@limiter.limit("30/minute")
def delete_credential(
    request: Request,
    response: Response,
    name: str,
    mattstash: MattStashDep,
    caller: DeleteAccess,
    _writes: WritesEnabled,
    _slot: WriteSlot,
    version: int | None = Query(None, ge=0, description="Delete only this version (default: all versions)"),
) -> dict[str, str]:
    """
    Delete a credential by name (all versions, or one version with ``?version=N``).

    - **name**: Credential name
    """
    require_valid_name(name)
    note(request, version=version)
    authorize_name(request, caller, "delete", "delete", name)
    response.headers["Cache-Control"] = "no-store"
    with translate_errors("delete"):
        deleted = mattstash.delete(name, version)

    if not deleted:
        raise _not_found(name)

    return {"detail": f"Credential deleted: {name}"}
