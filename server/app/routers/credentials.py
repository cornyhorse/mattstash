"""Credentials router for CRUD operations."""
from fastapi import APIRouter, HTTPException, Query, status

from mattstash.utils.exceptions import CredentialNotFoundError

from ..dependencies import APIKeyDep, MattStashDep
from ..models.responses import (
    CredentialListResponse,
    CredentialResponse,
    VersionListResponse,
)

router = APIRouter()


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
async def get_credential(  # pragma: no cover
    name: str,
    mattstash: MattStashDep,
    api_key: APIKeyDep,
    version: int | None = Query(None, description="Specific version to retrieve"),
    show_password: bool = Query(False, description="Show actual password instead of masking")
) -> CredentialResponse:
    """
    Get a specific credential by name.
    
    - **name**: Credential name
    - **version**: Optional version number
    - **show_password**: Whether to show the actual password (default: masked)
    """
    try:
        if version is not None:
            credential = mattstash.get_version(name, version)
        else:
            credential = mattstash.get(name)
        
        return credential_to_response(name, credential, show_password)
    
    except CredentialNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Credential not found: {name}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving credential: {str(e)}"
        )


@router.get("/credentials", response_model=CredentialListResponse)
async def list_credentials(  # pragma: no cover
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
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error listing credentials: {str(e)}"
        )


@router.get("/credentials/{name}/versions", response_model=VersionListResponse)
async def list_versions(  # pragma: no cover
    name: str,
    mattstash: MattStashDep,
    api_key: APIKeyDep
) -> VersionListResponse:
    """
    List all versions of a credential.
    
    - **name**: Credential name
    """
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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error listing versions: {str(e)}"
        )
