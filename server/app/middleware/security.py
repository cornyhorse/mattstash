"""Pure-ASGI security middleware (outermost layer).

For every HTTP request it:

1. refuses clients that have too many failed authentication attempts (429) *before* any auth or body
   handling happens;
2. enforces the request-body limit on the bytes actually received -- ``Content-Length`` is checked up
   front and the stream is counted, so chunked uploads cannot bypass the limit or be buffered unbounded;
3. adds security headers to every response;
4. records failed authentication (401) for throttling and writes one access-log line per request
   (method, path, status, duration, client address, key id -- never secrets, never the query string).
"""

import logging
import time
from collections.abc import MutableMapping
from typing import Any, Awaitable, Callable

from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse

from ..client_ip import client_ip
from ..config import config
from ..security.throttle import FailureTracker

logger = logging.getLogger("mattstash.api")

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

auth_failures = FailureTracker(lambda: config.AUTH_FAIL_LIMIT, lambda: config.AUTH_FAIL_WINDOW)


def _headers(raw: list[tuple[bytes, bytes]], name: bytes) -> list[bytes]:
    return [value for key, value in raw if key == name]


class SecurityMiddleware:
    def __init__(self, app: Callable[[Scope, Receive, Send], Awaitable[None]]) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started = time.monotonic()
        client = client_ip(scope)
        method, path = scope["method"], scope["path"]
        state: dict[str, Any] = {"status": 500}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                state["status"] = message["status"]
                present = {k.lower() for k, _ in message.get("headers", [])}
                headers = list(message.get("headers", []))
                for name, value in SECURITY_HEADERS.items():
                    if name.lower().encode() not in present:
                        headers.append((name.lower().encode(), value.encode()))
                message = {**message, "headers": headers}
            await send(message)

        # 1) throttle clients with too many failed authentications
        retry_after = auth_failures.retry_after(client)
        if retry_after:
            logger.warning("Throttled %s %s from %s (too many failed authentications)", method, path, client)
            response = JSONResponse(
                {"detail": "Too many failed authentication attempts"},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
            await response(scope, receive, send_wrapper)
            return

        # 2) body limit: declared length first, then count what actually arrives
        limit = config.MAX_REQUEST_BODY_BYTES
        raw_headers = scope.get("headers", [])
        declared = _headers(raw_headers, b"content-length")
        if declared:
            try:
                too_big = int(declared[0]) > limit
            except ValueError:
                await JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)(scope, receive, send_wrapper)
                return
            if too_big:
                await JSONResponse({"detail": "Request body too large"}, status_code=413)(scope, receive, send_wrapper)
                return

        received = 0

        async def receive_wrapper() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise HTTPException(status_code=413, detail="Request body too large")
            return message

        try:
            await self.app(scope, receive_wrapper, send_wrapper)
        except Exception as exc:
            logger.error("Unhandled error: %s %s - %s", method, path, type(exc).__name__)
            raise
        finally:
            status_code = state["status"]
            if status_code == 401:
                auth_failures.record_failure(client)
            principal = scope.get("state", {}).get("principal")
            logger.info(
                "%s %s -> %s (%.3fs) client=%s key=%s",
                method,
                path,
                status_code,
                time.monotonic() - started,
                client,
                principal.id if principal is not None else "-",
            )
