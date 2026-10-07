"""Health (liveness) and readiness routers. No authentication required."""

import logging

from fastapi import APIRouter, HTTPException, status

from ..config import config
from ..dependencies import get_mattstash
from ..models.responses import HealthResponse

logger = logging.getLogger("mattstash.api")
router = APIRouter()


@router.get("/health", response_model=HealthResponse, include_in_schema=False)
async def health_check() -> HealthResponse:
    """Liveness: the process is up and serving. Never touches the database."""
    return HealthResponse(status="healthy", version=config.API_VERSION)


@router.get("/ready", response_model=HealthResponse, include_in_schema=False)
def readiness_check() -> HealthResponse:
    """Readiness: the database can be opened and read. 503 otherwise (no details are disclosed)."""
    try:
        get_mattstash().list_versions("readiness-probe")
    except Exception as exc:
        logger.error("Readiness check failed: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Not ready",
        ) from None
    return HealthResponse(status="ready", version=config.API_VERSION)
