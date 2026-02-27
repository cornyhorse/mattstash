"""Credentials router for CRUD operations."""
import logging
import re

from fastapi import APIRouter, HTTPException, Query, Request, Response, status

from mattstash.utils.exceptions import CredentialNotFoundError

from ..dependencies import APIKeyDep, MattStashDep
from ..rate_limit import limiter
from ..models.responses import (
    CredentialListResponse,
    CredentialResponse,
    VersionListResponse,
)

logger = logging.getLogger("mattstash.api")
router = APIRouter()

# Validation pattern for credential names
_VALID_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]+$")
_MAX_NAME_LENGTH = 255


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


def mask_password(password: str) -> str:
    """Mask password for display."""
    return "*****"


def credential_to_response(
    name: str,
    credential: dict,
    show_password: bool = False
) -> CredentialResponse:
    """Convert credential dict to response model."""
    return CredentialResponse(
        name=name,
        username=credential.get("username"),
        password=credential["password"] if show_password else mask_password(credential["password"]),
        url=credential.get("url"),
        notes=credential.get("notes"),
        version=credential.get("version")
    )


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
        if version is not None:
            credential = mattstash.get_version(name, version)
        else:
            credential = mattstash.get(name)
        
        response_data = credential_to_response(name, credential, show_password)
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
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error retrieving credential %s: %s", name, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


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
        all_creds = mattstash.list()
        
        # Filter by prefix if provided
        if prefix:
            filtered_names = [name for name in all_creds if name.startswith(prefix)]
        else:
            filtered_names = all_creds
        
        # Get credential details
        credentials = []
        for name in filtered_names:
            try:
                cred = mattstash.get(name)
                credentials.append(
                    credential_to_response(name, cred, show_password)
                )
            except CredentialNotFoundError:
                # Skip if credential was deleted between list and get
                continue
        
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
        )


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
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error listing versions for %s: %s", name, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
