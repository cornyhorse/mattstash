"""Pure-ASGI security middleware (outermost layer).

For every HTTP request it:

1. **authenticates** everything except the health/readiness/docs paths, *before* the application (and its
   body parsing) runs. Doing it here means the throttle's check and its failure record happen back to back with
   no ``await`` in between, so a burst of concurrent requests cannot slip past the limit; and an unauthenticated
   request is answered ``401`` without its body ever being read;
2. refuses clients that already have too many failed authentications (``429``) before looking at the key;
3. enforces the request-body limit on the bytes actually received -- ``Content-Length`` is checked up front and
   the stream is counted, so chunked uploads cannot bypass the limit or be buffered unbounded;
4. adds security headers to every response (and ``Deprecation: true`` when a legacy key authenticated it);
5. writes the structured access-log line (app/accesslog.py) for every non-public request that the route has not
   already logged at its authorization decision (state-changing requests do that, before any effect): at
   ``http.response.start``, i.e. before any byte of the response is sent. If the log file refuses the line the
   response is replaced by ``503`` (fail closed). A request that ends without a response is logged from ``finally``
   with status 500, or with ``error: client-disconnected`` and no status when the client went away first.

The authentication result is stored in ``scope["state"]["auth"]`` for the route dependencies; routes add what they
decided to ``scope["state"]["access"]`` (:func:`app.accesslog.note`).
"""

import asyncio
import logging
import time
from collections.abc import MutableMapping
from typing import Any, Awaitable, Callable, Optional

from mattstash.authz import LEGACY_KIND
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse

from .. import accesslog
from ..client_ip import client_bucket, client_ip
from ..config import config
from ..logsafe import printable
from ..security.api_keys import AuthResult, authenticate
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


def _authenticate(raw_headers: list[tuple[bytes, bytes]]) -> AuthResult:
    value = _header(raw_headers, b"x-api-key")
    try:
        return authenticate(value.decode("latin-1") if value else None)
    except Exception as exc:  # unusable key store (e.g. unreadable file on first load): not the caller's fault
        logger.error("API key store unavailable: %s", type(exc).__name__)
        raise _KeyStoreUnavailable from None


def _masked(path: str) -> str:
    """The path for the log: a segment that starts like a token (``mst_``) is a secret pasted where an id belongs."""
    return "/".join("mst_…" if part.startswith("mst_") else part for part in path.split("/"))


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
        method, path = printable(scope["method"]), _masked(printable(scope["path"]))
        logged = scope["path"] not in public_paths()  # probes and docs are not access-logged
        status: dict[str, Any] = {"code": 500, "principal": "-", "legacy": False, "replaced": False}
        access = accesslog.access_state(scope)
        disconnected = False

        async def send_wrapper(message: Message) -> None:
            if status["replaced"]:
                return  # the app keeps talking after we answered 503 in its place
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
                if logged and not accesslog.is_written(scope) and not accesslog.write_line(scope, message["status"]):
                    status["replaced"], status["code"] = True, 503
                    body = b'{"detail":"Service temporarily unavailable"}'
                    message = {
                        "type": "http.response.start",
                        "status": 503,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode()),
                        ],
                    }
                    await send(self._with_security_headers(message, False))
                    await send({"type": "http.response.body", "body": body})
                    return
                message = self._with_security_headers(message, status["legacy"])
            await send(message)

        async def reply(content: dict[str, str], code: int, headers: Optional[dict[str, str]] = None) -> None:
            await JSONResponse(content, status_code=code, headers=headers)(scope, receive, send_wrapper)

        try:
            raw_headers: list[tuple[bytes, bytes]] = list(scope.get("headers", []))

            # 1) authentication + throttling for everything except the public paths. There is deliberately no
            #    await between asking "is this client blocked?" and recording a failure.
            if logged:
                retry_after = auth_failures.retry_after(bucket)
                if retry_after:
                    logger.warning("Throttled %s %s from %s (too many failed authentications)", method, path, client)
                    access.update(principal="-", decision="denied", reason="throttled")
                    await reply(
                        {"detail": "Too many failed authentication attempts"}, 429, {"Retry-After": str(retry_after)}
                    )
                    return
                try:
                    result = _authenticate(raw_headers)
                except _KeyStoreUnavailable:
                    access.update(principal="-", decision="denied", reason="auth-unavailable")
                    await reply({"detail": "Service temporarily unavailable"}, 503)
                    return
                if result.principal is None:
                    auth_failures.record_failure(bucket)
                    access.update(principal="-", token=result.token_id, decision="denied", reason=result.reason)
                    await reply({"detail": "Authentication failed"}, 401)
                    return
                status["principal"] = result.principal.name
                status["legacy"] = result.principal.kind == LEGACY_KIND
                access.update(principal=result.principal.name, kind=result.principal.kind, token=result.token_id)
                scope["state"]["auth"] = result

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
        except asyncio.CancelledError:
            disconnected = True  # the server cancels the request when the client goes away before the response
            raise
        except Exception as exc:
            logger.error("Unhandled error: %s %s - %s", method, path, type(exc).__name__)
            raise
        finally:
            if logged and not accesslog.is_written(scope):
                if disconnected:  # nothing was answered, so there is no status to report
                    status["code"] = "-"
                    accesslog.write_line(scope, error="client-disconnected")
                else:
                    accesslog.write_line(scope, 500)  # no response was started: the request crashed
            logger.info(
                "%s %s -> %s (%.3fs) client=%s key=%s",
                method,
                path,
                status["code"],
                time.monotonic() - started,
                client,
                status["principal"],
            )

    @staticmethod
    def _with_security_headers(message: Message, legacy: bool) -> Message:
        present = {k.lower() for k, _ in message.get("headers", [])}
        headers = list(message.get("headers", []))
        extra = dict(SECURITY_HEADERS)
        if legacy:
            extra["Deprecation"] = "true"  # find every caller still on a legacy key before they are switched off
        for name, value in extra.items():
            if name.lower().encode() not in present:
                headers.append((name.lower().encode(), value.encode()))
        return {**message, "headers": headers}
