"""Request/response logging middleware with credential masking."""
import logging
import re
import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from ..config import config
from ..rate_limit import get_client_address

logger = logging.getLogger("mattstash.api")


# Patterns to mask in logs
SENSITIVE_PATTERNS = [
    (re.compile(r'"password"\s*:\s*"[^"]*"'), '"password": "*****"'),
    (re.compile(r'"value"\s*:\s*"[^"]*"'), '"value": "*****"'),
    (re.compile(r'X-API-Key:\s*\S+'), 'X-API-Key: *****'),
]

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def mask_sensitive_data(text: str) -> str:
    """Mask sensitive data in log messages."""
    for pattern, replacement in SENSITIVE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log all requests and responses."""
    
    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        """Process request and log details."""
        # Start timer
        start_time = time.time()

        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > config.MAX_REQUEST_BODY_BYTES:
                    response = Response("Request body too large", status_code=413)
                    _apply_security_headers(response)
                    return response
            except ValueError:
                response = Response("Invalid Content-Length", status_code=400)
                _apply_security_headers(response)
                return response
        
        # Log request
        client_ip = get_client_address(request)
        method = request.method
        path = request.url.path
        
        logger.info("Request: %s %s from %s", method, path, client_ip)
        
        # Process request
        try:
            response = await call_next(request)
            
            # Calculate duration
            duration = time.time() - start_time
            
            # Log response (mask any sensitive data)
            log_msg = (
                f"Response: {method} {path} - "
                f"Status: {response.status_code} - "
                f"Duration: {duration:.3f}s"
            )
            logger.info(mask_sensitive_data(log_msg))
            _apply_security_headers(response)
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            error_msg = (
                f"Error: {method} {path} - "
                f"Exception: {type(e).__name__} - "
                f"Duration: {duration:.3f}s"
            )
            logger.error(mask_sensitive_data(error_msg))
            raise


def _apply_security_headers(response: Response) -> None:
    """Apply defense-in-depth headers to every API response."""
    for header, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
