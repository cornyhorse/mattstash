"""Credentials router for CRUD operations."""
import logging
import re
from typing import Any, Union

from fastapi import APIRouter, HTTPException, Query, Request, Response, status

from mattstash.models.credential import Credential
from mattstash.utils.exceptions import CredentialNotFoundError

from ..dependencies import APIKeyDep, MattStashDep
from ..models.requests import CreateCredentialRequest
from ..models.responses import (
    CreateCredentialResponse,
    CredentialListResponse,
    CredentialResponse,
    VersionListResponse,
)
from ..rate_limit import limiter

logger = logging.getLogger("mattstash.api")
router = APIRouter()

# Validation pattern for credential names
_VALID_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]+$")
_MAX_NAME_LENGTH = 255

_MASK = "*****"


def _validate_credential_name(name: str) -> None:
    """Validate credential name to prevent traversal attacks."""
    if not name or len(name) > _MAX_NAME_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid credential name"
        )
    if not _VALID_NAME_PATTERN.match(name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid credential name"
        )


def _normalize_credential(
    name: str,
    result: Union[Credential, dict[str, Any]],
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
            version=None,
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
@limiter.limit("60/minute")
async def get_credential(  # pragma: no cover
    request: Request,
    name: str,
    mattstash: MattStashDep,
    api_key: APIKeyDep,
    version: int | None = Query(None, description="Specific version to retrieve"),
    show_password: bool = Query(False, description="Show actual password instead of masking")
) -> Response:
    """
    Get a specific credential by name.

    - **name**: Credential name
    - **version**: Optional version number
    - **show_password**: Whether to show the actual password (default: masked)
    """
    _validate_credential_name(name)
    try:
        credential = mattstash.get(name, show_password=True, version=version)

        if credential is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Credential not found: {name}"
            )

        response_data = _normalize_credential(name, credential, show_password)
        response = Response(
            content=response_data.model_dump_json(),
            media_type="application/json",
            headers={"Cache-Control": "no-store"}
        )
        return response

    except CredentialNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Credential not found: {name}"
        ) from None
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error retrieving credential %s: %s", name, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        ) from None


@router.get("/credentials", response_model=CredentialListResponse)
@limiter.limit("30/minute")
async def list_credentials(  # pragma: no cover
    request: Request,
    mattstash: MattStashDep,
    api_key: APIKeyDep,
    prefix: str | None = Query(None, description="Filter by name prefix"),
    show_password: bool = Query(False, description="Show actual passwords instead of masking")
) -> CredentialListResponse:
    """
    List all credentials.

    - **prefix**: Optional prefix filter
    - **show_password**: Whether to show actual passwords (default: masked)
    """
    try:
        # mattstash.list() returns List[Credential]
        all_creds = mattstash.list(show_password=True)

        # Filter by prefix if provided
        if prefix:
            filtered = [
                c for c in all_creds
                if c.credential_name.startswith(prefix)
            ]
        else:
            filtered = all_creds

        credentials = [
            _normalize_credential(c.credential_name, c, show_password)
            for c in filtered
        ]

        return CredentialListResponse(
            credentials=credentials,
            count=len(credentials)
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error listing credentials: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        ) from None


@router.get("/credentials/{name}/versions", response_model=VersionListResponse)
@limiter.limit("60/minute")
async def list_versions(  # pragma: no cover
    request: Request,
    name: str,
    mattstash: MattStashDep,
    api_key: APIKeyDep
) -> VersionListResponse:
    """
    List all versions of a credential.

    - **name**: Credential name
    """
    _validate_credential_name(name)
    try:
        versions = mattstash.list_versions(name)

        if not versions:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Credential not found: {name}"
            )

        return VersionListResponse(
            name=name,
            versions=versions,
            latest=versions[-1]  # Last version is the latest
        )

    except CredentialNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Credential not found: {name}"
        ) from None
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error listing versions for %s: %s", name, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        ) from None


# ---------------------------------------------------------------------------
# POST / DELETE endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/credentials/{name}",
    response_model=CreateCredentialResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit("30/minute")
async def create_credential(  # pragma: no cover
    request: Request,
    name: str,
    body: CreateCredentialRequest,
    mattstash: MattStashDep,
    api_key: APIKeyDep,
) -> CreateCredentialResponse:
    """
    Create or update a credential.

    - **name**: Credential name
    """
    _validate_credential_name(name)
    try:
        result = mattstash.put(
            name,
            value=body.value,
            username=body.username,
            password=body.password,
            url=body.url,
            notes=body.notes,
        )

        if result is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to store credential"
            )

        # Determine version string from the result
        if isinstance(result, dict):
            version_str = result.get("version") or "0000000001"
        else:
            version_str = "0000000001"

        return CreateCredentialResponse(
            name=name,
            version=version_str,
            created=True,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error creating credential %s: %s", name, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        ) from None


@router.delete("/credentials/{name}", status_code=status.HTTP_200_OK)
@limiter.limit("30/minute")
async def delete_credential(  # pragma: no cover
    request: Request,
    name: str,
    mattstash: MattStashDep,
    api_key: APIKeyDep,
) -> dict[str, str]:
    """
    Delete a credential by name.

    - **name**: Credential name
    """
    _validate_credential_name(name)
    try:
        deleted = mattstash.delete(name)

        if not deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Credential not found: {name}"
            )

        return {"detail": f"Credential deleted: {name}"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error deleting credential %s: %s", name, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        ) from None
