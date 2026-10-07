"""Database URL builder router."""

import logging

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from mattstash.builders.db_url import build_db_url

from ..audit import audit
from ..dependencies import MattStashDep, ReadAccess, ensure_name_in_scope
from ..errors import translate_errors
from ..models.responses import DatabaseUrlResponse
from ..rate_limit import limiter, read_limit
from ..validation import require_valid_name

logger = logging.getLogger("mattstash.api")
router = APIRouter()

_ALLOWED_DRIVERS = {"psycopg", "psycopg2", "asyncpg", "pg8000"}
_DATABASE_NAME_MAX = 128


@router.get("/db-url/{name}", response_model=DatabaseUrlResponse)
@limiter.limit(read_limit)
def get_database_url(
    request: Request,
    response: Response,
    name: str,
    mattstash: MattStashDep,
    principal: ReadAccess,
    driver: str = Query("psycopg", description="PostgreSQL driver (psycopg, psycopg2, asyncpg, pg8000)"),
    database: str | None = Query(None, max_length=_DATABASE_NAME_MAX, description="Database name to append to URL"),
    mask_password: bool = Query(True, description="Mask password in the returned URL"),
) -> DatabaseUrlResponse:
    """
    Build a database connection URL from a credential.

    - **name**: Credential name
    - **driver**: Database driver (default: psycopg)
    - **database**: Optional database name
    - **mask_password**: Whether to mask the password in the URL (default: true)
    """
    require_valid_name(name)
    ensure_name_in_scope(principal, name, hide=True)
    response.headers["Cache-Control"] = "no-store"
    if driver not in _ALLOWED_DRIVERS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid driver name")
    audit(request, "db-url", name, reveal=not mask_password)

    with translate_errors("db-url"):
        try:
            url = build_db_url(
                mattstash=mattstash,
                name=name,
                driver=driver,
                database=database,
                mask_password=mask_password,
                mask_style="stars",
            )
        except ValueError as e:
            # build_db_url raises ValueError for missing creds / unsuitable entries. Handled here, inside the
            # translation context, so it is not mistaken for an unexpected error (500).
            err_msg = str(e).lower()
            if "not found" in err_msg or "simple secret" in err_msg:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Credential not found or unsuitable: {name}",
                ) from None
            logger.error("Error building database URL for %s: %s", name, type(e).__name__)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid credential for database URL construction",
            ) from None
    return DatabaseUrlResponse(url=url)
