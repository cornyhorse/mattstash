"""Pure-ASGI security middleware (outermost layer).

For every HTTP request it:

1. **authenticates** everything except the health/readiness/docs paths, *before* the application (and its
   body parsing) runs. Doing it here means the throttle's check and its failure record happen back to back with
   no ``await`` in between, so a burst of concurrent requests cannot slip past the limit; and an unauthenticated
   request is answered ``401`` without its body ever being read;
2. refuses clients that already have too many failed authentications (``429``) before looking at the key;
3. enforces the request-body limit on the bytes actually received -- ``Content-Length`` is checked up front and
   the stream is counted, so chunked uploads cannot bypass the limit or be buffered unbounded;
4. adds security headers to every response and writes one access-log line per request (method, path, status,
   duration, client address, key id -- never secrets, never the query string; untrusted text is escaped).

The principal found here is stored in ``scope["state"]["principal"]`` for the route dependencies and the audit log.
"""

import logging
import time
from collections.abc import MutableMapping
from typing import Any, Awaitable, Callable, Optional

from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse

from ..client_ip import client_bucket, client_ip
from ..config import config
from ..logsafe import printable
from ..security.api_keys import Principal, authenticate
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


def public_paths() -> frozenset[str]:
    """Paths that need no API key (and are never throttled): probes and, unless disabled, the API docs."""
    paths = {"/health", "/api/health", "/ready", "/api/ready"}
    if not config.DISABLE_DOCS:
        version = config.API_VERSION
        paths |= {f"/api/{version}/docs", f"/api/{version}/redoc", f"/api/{version}/openapi.json"}
        paths.add("/docs/oauth2-redirect")
    return frozenset(paths)


def _header(raw: list[tuple[bytes, bytes]], name: bytes) -> Optional[bytes]:
    for key, value in raw:
        if key == name:
            return value
    return None


class _KeyStoreUnavailable(Exception):
    pass


def _authenticate(raw_headers: list[tuple[bytes, bytes]]) -> Optional[Principal]:
    value = _header(raw_headers, b"x-api-key")
    if not value:
        return None
    try:
        return authenticate(value.decode("latin-1"))
    except Exception as exc:  # unusable key store (e.g. unreadable file on first load): not the caller's fault
        logger.error("API key store unavailable: %s", type(exc).__name__)
        raise _KeyStoreUnavailable from None


class SecurityMiddleware:
    def __init__(self, app: Callable[[Scope, Receive, Send], Awaitable[None]]) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started = time.monotonic()
        client = client_ip(scope)
        bucket = client_bucket(scope)
        method, path = printable(scope["method"]), printable(scope["path"])
        status: dict[str, Any] = {"code": 500, "principal": None}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
                present = {k.lower() for k, _ in message.get("headers", [])}
                headers = list(message.get("headers", []))
                for name, value in SECURITY_HEADERS.items():
                    if name.lower().encode() not in present:
                        headers.append((name.lower().encode(), value.encode()))
                message = {**message, "headers": headers}
            await send(message)

        async def reply(content: dict[str, str], code: int, headers: Optional[dict[str, str]] = None) -> None:
            await JSONResponse(content, status_code=code, headers=headers)(scope, receive, send_wrapper)

        try:
            raw_headers: list[tuple[bytes, bytes]] = list(scope.get("headers", []))

            # 1) authentication + throttling for everything except the public paths. There is deliberately no
            #    await between asking "is this client blocked?" and recording a failure.
            if scope["path"] not in public_paths():
                retry_after = auth_failures.retry_after(bucket)
                if retry_after:
                    logger.warning("Throttled %s %s from %s (too many failed authentications)", method, path, client)
                    await reply(
                        {"detail": "Too many failed authentication attempts"}, 429, {"Retry-After": str(retry_after)}
                    )
                    return
                try:
                    principal = _authenticate(raw_headers)
                except _KeyStoreUnavailable:
                    await reply({"detail": "Service temporarily unavailable"}, 503)
                    return
                if principal is None:
                    auth_failures.record_failure(bucket)
                    await reply({"detail": "Authentication failed"}, 401)
                    return
                status["principal"] = principal
                scope.setdefault("state", {})["principal"] = principal

            # 2) body limit: declared length first, then count what actually arrives
            limit = config.MAX_REQUEST_BODY_BYTES
            declared = _header(raw_headers, b"content-length")
            if declared is not None:
                try:
                    too_big = int(declared) > limit
                except ValueError:
                    await reply({"detail": "Invalid Content-Length"}, 400)
                    return
                if too_big:
                    await reply({"detail": "Request body too large"}, 413)
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

            await self.app(scope, receive_wrapper, send_wrapper)
        except Exception as exc:
            logger.error("Unhandled error: %s %s - %s", method, path, type(exc).__name__)
            raise
        finally:
            principal = status["principal"]
            logger.info(
                "%s %s -> %s (%.3fs) client=%s key=%s",
                method,
                path,
                status["code"],
                time.monotonic() - started,
                client,
                principal.id if principal is not None else "-",
            )
