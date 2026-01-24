"""Health check router."""
from fastapi import APIRouter

from ..config import config
from ..models.responses import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, include_in_schema=False)
async def health_check() -> HealthResponse:
    """
    Health check endpoint.
    
    No authentication required.
    """
    return HealthResponse(
        status="healthy",
        version=config.API_VERSION
    )
