"""Translate library errors into HTTP responses without leaking internals."""

import logging
from collections.abc import Iterator
from contextlib import contextmanager

from fastapi import HTTPException, status
from mattstash.utils.exceptions import (
    DatabaseAccessError,
    DatabaseLockError,
    DatabaseNotFoundError,
    InvalidCredentialError,
)

logger = logging.getLogger("mattstash.api")


@contextmanager
def translate_errors(action: str) -> Iterator[None]:
    """Map exceptions raised inside the block to safe HTTP errors.

    * database unavailable / locked  -> 503 (never "not found")
    * invalid credential data        -> 400 with the validation message (contains no secrets)
    * anything else                  -> 500 "Internal server error" (only the exception type is logged)
    """
    try:
        yield
    except HTTPException:
        raise
    except (DatabaseNotFoundError, DatabaseAccessError, DatabaseLockError) as exc:
        logger.error("Database unavailable during %s: %s", action, type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable",
            headers={"Retry-After": "5"},
        ) from None
    except InvalidCredentialError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from None
    except Exception as exc:
        logger.error("Error during %s: %s", action, type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from None
