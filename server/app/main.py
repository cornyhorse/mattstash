"""FastAPI application factory and main entry point."""
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from .config import config
from .dependencies import reload_mattstash_if_changed
from .middleware.logging import RequestLoggingMiddleware
from .rate_limit import limiter
from .routers import admin, credentials, db_url, health

logger = logging.getLogger("mattstash.api")


async def _poll_database_changes() -> None:
    """Background task that periodically checks for external KDBX changes."""
    interval = config.DB_POLL_INTERVAL
    if interval <= 0:
        logger.info("Database change polling disabled (interval=%d)", interval)
        return

    logger.info("Database change polling started (every %ds)", interval)
    while True:
        await asyncio.sleep(interval)
        try:
            if reload_mattstash_if_changed():
                logger.info("Database auto-reloaded after external modification")
        except Exception:
            logger.exception("Error during database change poll")


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

    # Start background poller for external DB modifications
    poller_task = asyncio.create_task(_poll_database_changes())

    yield

    # Shutdown
    poller_task.cancel()
    try:
        await poller_task
    except asyncio.CancelledError:
        pass
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
    app.include_router(
        admin.router,
        prefix=f"/api/{config.API_VERSION}",
        tags=["admin"]
    )

    return app


# Create app instance
app = create_app()
