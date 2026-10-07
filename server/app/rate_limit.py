"""Rate limiter configuration."""

from typing import Any

from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .client_ip import client_bucket
from .config import config


def get_client_address(request: Any) -> str:
    """Rate-limit identity: the client's throttling bucket (IPv4 address or IPv6 /64)."""
    return client_bucket(request.scope)


def read_limit() -> str:
    """Limit for read endpoints (``MATTSTASH_RATE_LIMIT``); evaluated per request so it can be reconfigured."""
    return config.RATE_LIMIT


# key_style="endpoint": the bucket is (client, route), not (client, concrete URL path). With slowapi's default
# ("url") every distinct secret name had its own bucket, so enumerating names or writing many secrets was never limited.
limiter = Limiter(key_func=get_client_address, default_limits=[config.RATE_LIMIT], key_style="endpoint")


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> Response:
    """429 with ``Retry-After`` (the full window of the limit that was hit: a safe upper bound)."""
    retry_after = 60
    try:
        retry_after = max(1, int(exc.limit.limit.get_expiry()))
    except Exception:  # unknown limit object shape: fall back to one minute
        pass
    return JSONResponse(
        {"error": f"Rate limit exceeded: {exc.detail}"}, status_code=429, headers={"Retry-After": str(retry_after)}
    )
