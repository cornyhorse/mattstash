"""Database URL builder router."""

import logging

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from mattstash.builders.db_url import AUTO_DRIVER, DIALECT_DRIVERS, DbUrlError, build_db_url, normalize_dialect

from ..audit import audit
from ..dependencies import MattStashDep, ReadAccess, ensure_name_in_scope
from ..errors import translate_errors
from ..models.responses import DatabaseUrlResponse
from ..rate_limit import limiter, read_limit
from ..validation import require_valid_name

logger = logging.getLogger("mattstash.api")
router = APIRouter()

_ALL_DRIVERS = frozenset().union(*DIALECT_DRIVERS.values())

#: What an entry/argument problem is reported as. Fixed texts only: nothing stored in the entry is echoed back.
_REASONS = {
    "missing-url": "the entry has no URL (host:port)",
    "missing-port": "the entry's URL has no port",
    "invalid-port": "the entry's URL has an invalid port",
    "invalid-host": "the entry's URL has an invalid host",
    "missing-database": "no database name: pass 'database' or set the entry's 'database' property",
    "invalid-sslmode": "the entry's sslmode is not a valid value",
    "sslmode-unsupported": "the entry sets sslmode, which only applies to PostgreSQL",
    "invalid-dialect": "the entry's 'dialect' property is not supported",
    "invalid-driver": "the driver is not valid for the entry's dialect",
}
_DATABASE_NAME_MAX = 128


@router.get("/db-url/{name}", response_model=DatabaseUrlResponse)
@limiter.limit(read_limit)
def get_database_url(
    request: Request,
    response: Response,
    name: str,
    mattstash: MattStashDep,
    principal: ReadAccess,
    driver: str | None = Query(
        None,
        description="Driver suffix. Default: psycopg for PostgreSQL, none for MySQL/MariaDB. "
        "PostgreSQL: psycopg, psycopg2, asyncpg, pg8000; MySQL: pymysql, mysqlconnector, asyncmy, aiomysql; "
        "MariaDB: mariadbconnector, pymysql",
    ),
    dialect: str | None = Query(
        None,
        description="postgresql, mysql or mariadb (default: the entry's 'dialect' property, else postgresql)",
    ),
    database: str | None = Query(None, max_length=_DATABASE_NAME_MAX, description="Database name to append to URL"),
    mask_password: bool = Query(True, description="Mask password in the returned URL"),
) -> DatabaseUrlResponse:
    """
    Build a database connection URL from a credential.

    - **name**: Credential name
    - **driver**: Database driver (default: psycopg for PostgreSQL, none otherwise)
    - **dialect**: postgresql (default), mysql or mariadb
    - **database**: Optional database name
    - **mask_password**: Whether to mask the password in the URL (default: true)
    """
    require_valid_name(name)
    ensure_name_in_scope(
        principal,
        name,
        hide=True,
        request=request,
        op="read",
        not_found_detail=f"Credential not found or unsuitable: {name}",  # same text as an in-scope miss
    )
    response.headers["Cache-Control"] = "no-store"
    try:
        chosen_dialect = normalize_dialect(dialect) if dialect else None
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid dialect name") from None
    # Same normalisation as the library ("PSYCOPG", " psycopg" work locally); "" means "no driver suffix".
    driver = driver.strip().lower() if driver is not None else None
    if driver and driver != AUTO_DRIVER:
        allowed = DIALECT_DRIVERS[chosen_dialect] if chosen_dialect else _ALL_DRIVERS
        if driver not in allowed:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid driver name")
    audit(request, "db-url", name, reveal=not mask_password)

    with translate_errors("db-url"):
        try:
            url = build_db_url(
                mattstash=mattstash,
                name=name,
                driver=AUTO_DRIVER if driver is None else driver,
                dialect=chosen_dialect,
                database=database,
                mask_password=mask_password,
                mask_style="stars",
            )
        except DbUrlError as e:
            # Raised for entries that cannot produce a URL. Handled inside the translation context so it is not
            # mistaken for an unexpected error (500); the reason code selects a fixed, value-free message.
            if e.reason in ("not-found", "simple-secret"):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Credential not found or unsuitable: {name}",
                ) from None
            logger.error("Error building database URL for %s: %s", name, e.reason)
            reason = _REASONS.get(e.reason, "invalid entry configuration")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Entry cannot be used for a database URL: {reason}",
            ) from None
        except ValueError as e:
            logger.error("Error building database URL for %s: %s", name, type(e).__name__)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid credential for database URL construction",
            ) from None
    return DatabaseUrlResponse(url=url)
