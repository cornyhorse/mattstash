"""Request/response logging middleware with credential masking."""
import logging
import re
import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("mattstash.api")


# Patterns to mask in logs
SENSITIVE_PATTERNS = [
    (re.compile(r'"password"\s*:\s*"[^"]*"'), '"password": "*****"'),
    (re.compile(r'"value"\s*:\s*"[^"]*"'), '"value": "*****"'),
    (re.compile(r'X-API-Key:\s*\S+'), 'X-API-Key: *****'),
]


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
        
        # Log request
        client_ip = request.client.host if request.client else "unknown"
        method = request.method
        path = request.url.path
        
        logger.info(f"Request: {method} {path} from {client_ip}")
        
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
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            error_msg = (
                f"Error: {method} {path} - "
                f"Exception: {type(e).__name__}: {str(e)} - "
                f"Duration: {duration:.3f}s"
            )
            logger.error(mask_sensitive_data(error_msg))
            raise
