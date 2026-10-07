"""FastAPI application factory and main entry point."""

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from limits import parse_many
from mattstash.models.config import config as lib_config
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from .config import config
from .dependencies import initialize_mattstash, reload_mattstash_if_changed
from .logging_setup import configure_logging
from .middleware.security import SecurityMiddleware
from .rate_limit import limiter
from .routers import admin, credentials, db_url, health
from .security.api_keys import get_key_policy

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
            # Reloading decrypts the database (~0.5 s): keep it off the event loop.
            if await asyncio.to_thread(reload_mattstash_if_changed):
                logger.info("Database auto-reloaded after external modification")
        except Exception:
            logger.exception("Error during database change poll")


def _check_sidecar() -> None:
    """The master password must not sit next to the database it protects (nor a backup of it)."""
    directory = os.path.dirname(os.path.expanduser(config.DB_PATH)) or "."
    try:
        found = [n for n in os.listdir(directory) if n.startswith(lib_config.sidecar_basename)]
    except OSError:
        return
    if not found:
        return
    message = (
        f"Plaintext password file(s) {sorted(found)} exist next to the database; anyone who can read the data "
        "volume can open it. Delete them (backups of the sidecar included) and supply the password via "
        "KDBX_PASSWORD_FILE from a separate mount."
    )
    if config.REFUSE_SIDECAR:
        raise RuntimeError(message + " (refusing to start: MATTSTASH_REFUSE_SIDECAR is set)")
    logger.warning(message)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting %s", config.API_TITLE)

    # Validate configuration (do not log paths, keys or raw errors)
    try:
        config.get_kdbx_password()
        policy = get_key_policy(force=True)
        config.validate_tls()
        try:
            parse_many(config.RATE_LIMIT)
        except Exception:
            raise ValueError(f"MATTSTASH_RATE_LIMIT is not a valid rate limit: {config.RATE_LIMIT!r}") from None
        logger.info("Configuration validated successfully (%d API key(s))", len(policy))
    except Exception:
        logger.error("Configuration validation failed - check environment variables")
        raise

    if policy.legacy_count:
        logger.warning(
            "%d legacy API key(s) with FULL access are configured; migrate to a scoped key policy "
            "(see server/docs/configuration.md) and set MATTSTASH_REQUIRE_SCOPED_KEYS=true",
            policy.legacy_count,
        )
    _check_sidecar()

    # Open the database now so a wrong password / missing file fails the deployment visibly,
    # instead of surfacing as errors on the first request.
    try:
        await asyncio.to_thread(initialize_mattstash)
    except Exception as exc:
        logger.error("Cannot open the database: %s - %s", type(exc).__name__, exc)
        raise

    if config.ALLOW_WRITES:
        logger.warning(
            "Writes are ENABLED. Run a single replica; the data directory must be writable (a lock file is created)."
        )
        if not os.access(os.path.dirname(config.DB_PATH) or ".", os.W_OK):
            logger.warning("MATTSTASH_ALLOW_WRITES is set but the data directory is not writable")
    else:
        logger.info("Read-only mode (set MATTSTASH_ALLOW_WRITES=true to enable writes)")

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


async def _validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """422 with only where/what/why: FastAPI's default body echoes the submitted values, i.e. the secrets."""
    errors = [{"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]} for e in exc.errors()]
    return JSONResponse({"detail": errors}, status_code=422)


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    configure_logging()
    docs = not config.DISABLE_DOCS
    app = FastAPI(
        title=config.API_TITLE,
        description=config.API_DESCRIPTION,
        version=config.API_VERSION,
        lifespan=lifespan,
        docs_url=f"/api/{config.API_VERSION}/docs" if docs else None,
        redoc_url=f"/api/{config.API_VERSION}/redoc" if docs else None,
        openapi_url=f"/api/{config.API_VERSION}/openapi.json" if docs else None,
    )

    # Rate limiting (per client address)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_exception_handler(RequestValidationError, _validation_error_handler)

    # Add CORS middleware (restrictive by default)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[],  # No origins allowed by default
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["X-API-Key"],
    )

    # Outermost layer: failed-auth throttling, streaming body limit, security headers, access log.
    app.add_middleware(SecurityMiddleware)

    # Health/readiness are served both at the root (probes, README) and under /api (historic path).
    app.include_router(health.router)
    app.include_router(health.router, prefix="/api")
    app.include_router(credentials.router, prefix=f"/api/{config.API_VERSION}", tags=["credentials"])
    app.include_router(db_url.router, prefix=f"/api/{config.API_VERSION}", tags=["database"])
    app.include_router(admin.router, prefix=f"/api/{config.API_VERSION}", tags=["admin"])

    return app


# Create app instance
app = create_app()
