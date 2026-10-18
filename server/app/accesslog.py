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
* when ``MATTSTASH_ACCESS_LOG_FILE`` is set, a rotating file (mode 0600) that fails CLOSED by default: if a line
  cannot be written the caller refuses the request. With ``MATTSTASH_ACCESS_LOG_FAIL_OPEN=true`` a failed file write is
  logged as an error instead, the stdout line (marked ``error: access-log-write-failed``) is still emitted and the
  request proceeds. Either way the sink's health is tracked (:func:`sink_healthy`) and ``/ready`` answers 503 while
  it is unhealthy. That is why the file is not written through ``logging`` handlers: they
  swallow write errors (``Handler.handleError``), and here an error must reach the middleware.

Nothing secret is ever passed in: names, decisions and token ids only.
"""

import contextlib
import errno
import logging
import os
import threading
import time
from collections.abc import Mapping, MutableMapping
from logging.handlers import RotatingFileHandler
from typing import Any, Optional

from fastapi import HTTPException, Request, status
from mattstash.authz import GAP_EVENT, PROBE_EVENT, format_record, now_iso

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
    """Opens (and, after each rotation, re-opens) the file with mode 0600, whatever the umask is.

    The stream is UNBUFFERED binary: a line reaches the kernel in the write itself, so a failed write leaves nothing
    in a Python buffer that a later flush could write out after the request it belonged to was answered 503.
    """

    def _open(self):  # type: ignore[no-untyped-def]
        # O_NONBLOCK: opening a named pipe nobody reads must fail at once, not park a worker thread for good.
        descriptor = os.open(self.baseFilename, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NONBLOCK, 0o600)
        with contextlib.suppress(OSError):  # tighten a file that already existed; not possible if it is not ours
            os.fchmod(descriptor, 0o600)
        return os.fdopen(descriptor, "ab", buffering=0)


#: ``/ready`` tries a failing sink again at most this often (seconds); in between it answers from the cached flag.
READY_PROBE_INTERVAL = 5.0
#: The "Access log write failed" error is logged for the first failure and then at most this often (seconds).
FAILURE_REPORT_INTERVAL = 60.0
_NEVER = float("-inf")


def _now() -> float:
    return time.monotonic()


class FileSink:
    """Appends lines to a rotating file; raises on any failure.

    After a failed write the file is closed (whatever was half written is dropped with the stream) and opened again at
    the next write, so a recovered disk, a replaced file or a rotated-away descriptor all heal on their own. A
    fragment of a line a failing disk accepted is ended with a newline before the next line, so it cannot swallow it.
    The first line written after a failure is preceded by one ``access-log-gap`` event that says how many request
    lines the file missed.
    """

    def __init__(self, path: str, max_bytes: int, backups: int) -> None:
        self._handler = _PrivateRotatingHandler(
            path, mode="a", maxBytes=max_bytes, backupCount=backups, encoding="utf-8", delay=False
        )
        self._lock = threading.Lock()
        self._healthy = True  # False after a failed write or open, until a write succeeds; changes under _lock
        self._lost = 0  # request lines the file missed since it last wrote one; changes under _lock
        self._torn = False  # the last failed write may have left a partial line
        self.last_probe = _NEVER

    @property
    def healthy(self) -> bool:
        with self._lock:
            return self._healthy

    def _put(self, line: str) -> None:
        """Append one line (under the lock): reopen if needed, rotate if due, write all of it."""
        handler = self._handler
        if handler.stream is None:
            handler.stream = handler._open()
        if handler.shouldRollover(logging.makeLogRecord({"msg": line})):
            handler.doRollover()
        data = memoryview((("\n" if self._torn else "") + line + "\n").encode("utf-8"))
        while data:  # an unbuffered write may be partial
            written = handler.stream.write(data)
            if not written:
                raise OSError(errno.EIO, "the log file accepted no bytes")
            data = data[written:]
            if data:
                self._torn = True  # a fragment is in the file now; if the rest fails, the next line starts afresh
        self._torn = False

    def write(self, line: str) -> None:
        with self._lock:
            try:
                if self._lost:
                    self._put(format_record({"ts": now_iso(), "event": GAP_EVENT, "lost": self._lost}))
                    self._lost = 0
                self._put(line)
            except Exception:
                self._discard()
                raise

    def _discard(self) -> None:
        """After a failed write (lock held): drop the stream; the next write opens the file afresh."""
        self._healthy = False
        handler = self._handler
        stream, handler.stream = handler.stream, None
        if stream is not None:
            with contextlib.suppress(OSError, ValueError):
                stream.close()

    def record_failure(self, lost_line: bool = True) -> None:
        """A write through this sink failed (the caller saw the exception)."""
        with self._lock:
            self._healthy = False
            if lost_line:
                self._lost += 1

    def record_success(self) -> None:
        with self._lock:
            self._healthy = True

    def close(self) -> None:
        with self._lock, contextlib.suppress(OSError, ValueError):  # shutting down: a broken stream is not news
            self._handler.close()


_sink: Optional[FileSink] = None
#: True when the file could not be opened at startup (the server then does not start).
_open_failed = False
_report_lock = threading.Lock()
_last_report = _NEVER
_failures_unreported = 0


def open_file_sink() -> None:
    """Open the configured file (startup: a bad path stops the server instead of failing every request)."""
    global _sink, _open_failed, _last_report, _failures_unreported
    close_file_sink()
    _open_failed = False
    with _report_lock:
        _last_report, _failures_unreported = _NEVER, 0
    if config.ACCESS_LOG_FILE:
        try:
            _sink = FileSink(config.ACCESS_LOG_FILE, config.ACCESS_LOG_MAX_BYTES, config.ACCESS_LOG_BACKUPS)
        except Exception:
            _open_failed = True
            raise


def close_file_sink() -> None:
    global _sink
    sink, _sink = _sink, None
    if sink is not None:
        sink.close()


def sink_healthy() -> bool:
    """False while the last attempt to write the access-log file failed (and none has succeeded since)."""
    sink = _sink
    return not _open_failed and (sink is None or sink.healthy)


def _report_failure(exc: Exception) -> None:
    """Log "Access log write failed" for the first failure, then at most once per minute, with how many there were."""
    global _last_report, _failures_unreported
    with _report_lock:
        _failures_unreported += 1
        now = _now()
        if now - _last_report < FAILURE_REPORT_INTERVAL:
            return
        count, _failures_unreported, _last_report = _failures_unreported, 0, now
    logger.error("Access log write failed: %s (%d failure(s) since the last report)", type(exc).__name__, count)


def probe_sink() -> bool:
    """Is the file sink usable? A healthy sink answers from the last write. An unhealthy one is tried again with a
    small marker line, so a pod taken out of rotation (no traffic, so no writes) can recover, but at most once every
    :data:`READY_PROBE_INTERVAL` seconds; in between the cached flag (unhealthy) is the answer, so a monitor polling
    ``/ready`` cannot hammer a failing disk. Never raises."""
    sink = _sink
    if sink is None:
        return True
    with sink._lock:
        if sink._healthy:
            return True
        now = _now()
        if now - sink.last_probe < READY_PROBE_INTERVAL:
            return False
        sink.last_probe = now
    try:
        sink.write(format_record({"ts": now_iso(), "event": PROBE_EVENT}))
    except Exception as exc:
        sink.record_failure(lost_line=False)
        _report_failure(exc)
        return False
    sink.record_success()
    return True


def emit(fields: Mapping[str, object]) -> None:
    """Write one line to the file (if any), then stdout. Raises if the file write fails (nothing reaches stdout)."""
    line = format_record(fields)
    sink = _sink
    if sink is not None:
        try:
            sink.write(line)
        except Exception:
            sink.record_failure()
            raise
        sink.record_success()
    access_logger.info(line)


def emit_failed(fields: Mapping[str, object]) -> None:
    """Stdout only: the file refused the line. Failing closed, the request was answered 503 instead of what the route
    decided (so the line says 503); failing open, it proceeds and the line keeps its own status."""
    extra: dict[str, object] = {"error": "access-log-write-failed"}
    if not config.ACCESS_LOG_FAIL_OPEN:
        extra["status"] = 503
    access_logger.info(format_record({**fields, **extra}))


def write_line(scope: MutableMapping[str, Any], code: Optional[int] = None, error: Optional[str] = None) -> bool:
    """Write this request's one line (``code`` and ``error`` become ``status`` and ``error`` when given).

    False if the file sink refused it and the log fails closed (the caller refuses the request); the line then goes to
    stdout alone, marked ``status: 503``. With ``MATTSTASH_ACCESS_LOG_FAIL_OPEN`` the same failure is logged as an
    error, the stdout line is marked ``error: access-log-write-failed`` and this returns True. The request counts as
    written either way, so nothing writes a second line for it.
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
        _report_failure(exc)
        emit_failed(fields)
        return config.ACCESS_LOG_FAIL_OPEN
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
