"""Database URL builder router."""
from fastapi import APIRouter, HTTPException, Query, status

from mattstash.builders.db_url import build_db_url
from mattstash.utils.exceptions import CredentialNotFoundError

from ..dependencies import APIKeyDep, MattStashDep
from ..models.responses import DatabaseUrlResponse

router = APIRouter()


@router.get("/db-url/{name}", response_model=DatabaseUrlResponse)
async def get_database_url(
    name: str,
    mattstash: MattStashDep,
    api_key: APIKeyDep,
    driver: str = Query("psycopg", description="Database driver (e.g., psycopg, mysqldb, pymongo)"),
    database: str | None = Query(None, description="Database name to append to URL"),
    mask_password: bool = Query(True, description="Mask password in the returned URL")
) -> DatabaseUrlResponse:
    """
    Build a database connection URL from a credential.
    
    - **name**: Credential name
    - **driver**: Database driver (default: psycopg)
    - **database**: Optional database name
    - **mask_password**: Whether to mask the password in the URL (default: true)
    """
    try:
        # Build the URL
        url = build_db_url(
            mattstash=mattstash,
            name=name,
            driver=driver,
            database=database
        )
        
        # Mask password if requested
        if mask_password and "@" in url:
            # Replace password in URL with *****
            # Format: scheme://user:password@host...
            parts = url.split("://", 1)
            if len(parts) == 2:
                scheme, rest = parts
                if "@" in rest:
                    creds_and_host = rest.split("@", 1)
                    if len(creds_and_host) == 2:
                        creds, host = creds_and_host
                        if ":" in creds:
                            user, _ = creds.split(":", 1)
                            url = f"{scheme}://{user}:*****@{host}"
        
        return DatabaseUrlResponse(url=url)
    
    except CredentialNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Credential not found: {name}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error building database URL: {str(e)}"
        )
