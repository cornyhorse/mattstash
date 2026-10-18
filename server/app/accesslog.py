"""The structured access log (docs/design/principals-and-grants.md section 6).

One JSON line per request, built from what the route recorded in ``scope["state"]["access"]`` (see :func:`note`).
When it is written depends on the request:

* a state-changing request (POST/PATCH/PUT/DELETE) that reaches an authorization decision gets its line AT THE
  DECISION, from the route's dependency (:func:`commit`), before any effect. If the line cannot be written the
  request is answered 503 and the handler never runs, so nothing changed and no token was minted. Such a line has no
  ``status``: it is written before the outcome is known;
* every other request (reads, and anything rejected before a decision) is written by the security middleware at
  ``http.response.start``, with the ``status`` being sent, i.e. before any byte of the response goes out. A read
  whose line cannot be written is not sent either.

Either way a request produces exactly one line (:func:`write_line` marks it written). Sinks:

* the ``mattstash.access`` logger, which :func:`app.logging_setup.configure_logging` points at stdout, always;
* when ``MATTSTASH_ACCESS_LOG_FILE`` is set, a rotating file (mode 0600) that fails CLOSED: if a line cannot be
  written the caller refuses the request. That is why the file is not written through ``logging`` handlers: they
  swallow write errors (``Handler.handleError``), and here an error must reach the middleware.

Nothing secret is ever passed in: names, decisions and token ids only.
"""

import contextlib
import logging
import os
import threading
from collections.abc import Mapping, MutableMapping
from logging.handlers import RotatingFileHandler
from typing import Any, Optional

from fastapi import HTTPException, Request, status
from mattstash.authz import format_record, now_iso

from .client_ip import client_ip
from .config import config

ACCESS_LOGGER = "mattstash.access"
access_logger = logging.getLogger(ACCESS_LOGGER)
logger = logging.getLogger("mattstash.api")

#: Fields a route may add to its request's line. The middleware owns the rest (ts, principal, kind, token, ...).
_ROUTE_FIELDS = frozenset(
    {
        "action",
        "route",
        "key",
        "tag",
        "decision",
        "reason",
        "grant",
        "count",
        "target_token",  # admin: the id (never the secret) of the token being revoked or rotated
        "grant_key",  # admin: the pattern / tag / actions of a grant being added (not secret)
        "grant_tag",
        "actions",
        "reveal",  # a secret value was returned (show_password, unmasked db-url)
        "version",  # a specific version was requested
    }
)
STATE_CHANGING = frozenset({"POST", "PATCH", "PUT", "DELETE"})


def access_state(scope: MutableMapping[str, Any]) -> dict[str, Any]:
    """The mutable per-request record (created on first use)."""
    record: dict[str, Any] = scope.setdefault("state", {}).setdefault("access", {})
    return record


def note(request: Request, **fields: object) -> None:
    """Record what the route decided; it ends up in this request's access-log line."""
    unknown = set(fields) - _ROUTE_FIELDS
    if unknown:  # a typo here would silently drop audit data
        raise ValueError(f"unknown access-log fields: {sorted(unknown)}")
    access_state(request.scope).update(fields)


class _PrivateRotatingHandler(RotatingFileHandler):
    """Opens (and, after each rotation, re-opens) the file with mode 0600, whatever the umask is."""

    def _open(self):  # type: ignore[no-untyped-def]
        descriptor = os.open(self.baseFilename, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with contextlib.suppress(OSError):  # tighten a file that already existed; not possible if it is not ours
            os.fchmod(descriptor, 0o600)
        return os.fdopen(descriptor, self.mode, encoding=self.encoding, errors=self.errors)


class FileSink:
    """Appends lines to a rotating file; raises on any failure."""

    def __init__(self, path: str, max_bytes: int, backups: int) -> None:
        self._handler = _PrivateRotatingHandler(
            path, mode="a", maxBytes=max_bytes, backupCount=backups, encoding="utf-8", delay=False
        )
        self._lock = threading.Lock()

    def write(self, line: str) -> None:
        record = logging.makeLogRecord({"msg": line})  # only used by shouldRollover to measure the line
        with self._lock:
            if self._handler.shouldRollover(record):
                self._handler.doRollover()
            stream = self._handler.stream
            stream.write(line + "\n")
            stream.flush()

    def close(self) -> None:
        with self._lock, contextlib.suppress(OSError, ValueError):  # shutting down: a broken stream is not news
            self._handler.close()


_sink: Optional[FileSink] = None


def open_file_sink() -> None:
    """Open the configured file (startup: a bad path stops the server instead of failing every request)."""
    global _sink
    close_file_sink()
    if config.ACCESS_LOG_FILE:
        _sink = FileSink(config.ACCESS_LOG_FILE, config.ACCESS_LOG_MAX_BYTES, config.ACCESS_LOG_BACKUPS)


def close_file_sink() -> None:
    global _sink
    sink, _sink = _sink, None
    if sink is not None:
        sink.close()


def emit(fields: Mapping[str, object]) -> None:
    """Write one line to the file (if any), then stdout. Raises if the file write fails (nothing reaches stdout)."""
    line = format_record(fields)
    sink = _sink
    if sink is not None:
        sink.write(line)
    access_logger.info(line)


def emit_failed(fields: Mapping[str, object]) -> None:
    """Stdout only: the file refused the line, so the request was answered 503 instead of what the route decided."""
    access_logger.info(format_record({**fields, "status": 503, "error": "access-log-write-failed"}))


def write_line(scope: MutableMapping[str, Any], code: Optional[int] = None, error: Optional[str] = None) -> bool:
    """Write this request's one line (``code`` and ``error`` become ``status`` and ``error`` when given).

    False if the file sink refused it; the line then goes to stdout alone, marked ``status: 503``. The request counts
    as written either way, so nothing writes a second line for it.
    """
    scope.setdefault("state", {})["access_written"] = True
    fields: dict[str, object] = {"ts": now_iso(), **access_state(scope), "client": client_ip(scope)}
    if code is not None:
        fields["status"] = code
    if error is not None:
        fields["error"] = error
    try:
        emit(fields)
    except Exception as exc:
        logger.error("Access log write failed: %s", type(exc).__name__)
        emit_failed(fields)
        return False
    return True


def is_written(scope: MutableMapping[str, Any]) -> bool:
    return bool(scope.get("state", {}).get("access_written"))


def commit(request: Request) -> None:
    """Fail closed at the authorization decision of a state-changing request: write its line now, before any effect.

    A no-op for other methods (their line is written with the response status by the middleware). Raises 503 if the
    line cannot be written, which stops the request before its handler changes anything.
    """
    if request.method in STATE_CHANGING and not is_written(request.scope) and not write_line(request.scope):
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Service temporarily unavailable")
