"""Credentials router for CRUD operations.

All handlers are plain ``def`` (not ``async def``): the KeePass work (decrypting, re-encrypting and
saving the database takes ~0.5 s) therefore runs in FastAPI's threadpool instead of blocking the
event loop, so health probes and other requests stay responsive while a write is in progress.
"""

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from mattstash.models.credential import Credential

from ..audit import audit
from ..dependencies import (
    DeleteAccess,
    MattStashDep,
    ReadAccess,
    WriteAccess,
    WritesEnabled,
    ensure_name_in_scope,
)
from ..errors import translate_errors
from ..models.requests import CreateCredentialRequest
from ..models.responses import (
    CreateCredentialResponse,
    CredentialListResponse,
    CredentialResponse,
    VersionListResponse,
)
from ..rate_limit import limiter, read_limit
from ..validation import is_valid_name, require_valid_name, require_valid_prefix

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
    principal: ReadAccess,
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
    ensure_name_in_scope(principal, name, hide=True, request=request, op="read")
    audit(request, "get", name, reveal=show_password, version=version)
    with translate_errors("get"):
        credential = mattstash.get(name, show_password=True, version=version)

    if credential is None:
        raise _not_found(name)

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
    principal: ReadAccess,
    prefix: str | None = Query(None, description="Filter by name prefix"),
    show_password: bool = Query(False, description="Show actual passwords instead of masking"),
) -> CredentialListResponse:
    """
    List credentials (latest version of each) that this key may read.

    - **prefix**: Optional prefix filter
    - **show_password**: Whether to show actual passwords (default: masked)

    Entries whose titles contain characters outside ``[A-Za-z0-9_.-]`` are not addressable through this
    API and are not listed.
    """
    response.headers["Cache-Control"] = "no-store"
    if prefix:
        require_valid_prefix(prefix)
    audit(request, "list", reveal=show_password, prefix=prefix)
    with translate_errors("list"):
        all_creds = mattstash.list(show_password=True, latest_only=True)

    visible = [
        c
        for c in all_creds
        if is_valid_name(c.credential_name)
        and principal.allows_name(c.credential_name)
        and (not prefix or c.credential_name.startswith(prefix))
    ]
    credentials = [_normalize_credential(c.credential_name, c, show_password) for c in visible]
    return CredentialListResponse(credentials=credentials, count=len(credentials))


@router.get("/credentials/{name}/versions", response_model=VersionListResponse)
@limiter.limit(read_limit)
def list_versions(
    request: Request,
    name: str,
    mattstash: MattStashDep,
    principal: ReadAccess,
) -> VersionListResponse:
    """
    List all versions of a credential.

    - **name**: Credential name
    """
    require_valid_name(name)
    ensure_name_in_scope(principal, name, hide=True, request=request, op="read")
    audit(request, "versions", name)
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
    principal: WriteAccess,
    _writes: WritesEnabled,
) -> CreateCredentialResponse:
    """
    Create a new version of a credential (or the first one).

    - **name**: Credential name
    """
    require_valid_name(name)
    ensure_name_in_scope(principal, name, hide=False, request=request, op="write")
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
    audit(request, "put", name, version=version)
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
    principal: DeleteAccess,
    _writes: WritesEnabled,
    version: int | None = Query(None, ge=0, description="Delete only this version (default: all versions)"),
) -> dict[str, str]:
    """
    Delete a credential by name (all versions, or one version with ``?version=N``).

    - **name**: Credential name
    """
    require_valid_name(name)
    ensure_name_in_scope(principal, name, hide=False, request=request, op="delete")
    response.headers["Cache-Control"] = "no-store"
    with translate_errors("delete"):
        deleted = mattstash.delete(name, version)
    audit(request, "delete", name, version=version, deleted=deleted)

    if not deleted:
        raise _not_found(name)

    return {"detail": f"Credential deleted: {name}"}
