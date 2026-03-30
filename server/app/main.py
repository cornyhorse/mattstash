"""FastAPI application factory and main entry point."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from .config import config
from .middleware.logging import RequestLoggingMiddleware
from .rate_limit import limiter
from .routers import credentials, db_url, health

logger = logging.getLogger("mattstash.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting %s", config.API_TITLE)

    # Validate configuration (do not log paths or raw errors)
    try:
        config.get_kdbx_password()
        config.get_api_keys()
        logger.info("Configuration validated successfully")
    except Exception:
        logger.error(
            "Configuration validation failed"
            " — check environment variables"
        )
        raise

    yield

    # Shutdown
    logger.info("Shutting down MattStash API")


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    app = FastAPI(
        title=config.API_TITLE,
        description=config.API_DESCRIPTION,
        version=config.API_VERSION,
        lifespan=lifespan,
        docs_url=f"/api/{config.API_VERSION}/docs",
        redoc_url=f"/api/{config.API_VERSION}/redoc",
        openapi_url=f"/api/{config.API_VERSION}/openapi.json"
    )

    # Add rate limiting
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Add CORS middleware (restrictive by default)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[],  # No origins allowed by default
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["X-API-Key"],
    )

    # Add request logging middleware
    app.add_middleware(RequestLoggingMiddleware)

    # Include routers
    app.include_router(health.router, prefix="/api", tags=["health"])
    app.include_router(
        credentials.router,
        prefix=f"/api/{config.API_VERSION}",
        tags=["credentials"]
    )
    app.include_router(
        db_url.router,
        prefix=f"/api/{config.API_VERSION}",
        tags=["database"]
    )

    return app


# Create app instance
app = create_app()
