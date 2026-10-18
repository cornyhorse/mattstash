"""The structured access log (docs/design/principals-and-grants.md section 6).

One JSON line per request, written by the security middleware at ``http.response.start`` from what the route recorded
in ``scope["state"]["access"]`` (see :func:`note`). Sinks:

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

from fastapi import Request
from mattstash.authz import format_record

from .config import config

ACCESS_LOGGER = "mattstash.access"
access_logger = logging.getLogger(ACCESS_LOGGER)
logger = logging.getLogger("mattstash.api")

#: Fields a route may add to its request's line. The middleware owns the rest (ts, principal, kind, token, ...).
_ROUTE_FIELDS = frozenset({"action", "route", "key", "tag", "decision", "reason", "grant", "count"})


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
