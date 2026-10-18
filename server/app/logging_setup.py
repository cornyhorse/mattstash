"""Logging for the server process.

``uvicorn`` only configures its own loggers, so without this nothing would be emitted by a real deployment:

* ``mattstash.api``    - operational messages, level from ``MATTSTASH_LOG_LEVEL`` (default info), to stderr;
* ``mattstash.access`` - the structured access log: one JSON line per request, to stdout, message only (the line
  is the JSON object). **Always INFO**: the access log is not optional and is not silenced by
  ``MATTSTASH_LOG_LEVEL=warning``. The optional file sink lives in :mod:`app.accesslog`.
"""

import logging
import sys

from .accesslog import ACCESS_LOGGER
from .config import config

_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
_MARKER = "_mattstash_server_handler"


class _StdoutHandler(logging.StreamHandler):  # type: ignore[type-arg]
    """Writes to whatever ``sys.stdout`` is *now* (like logging's own stderr handler), not when it was created."""

    def __init__(self) -> None:
        logging.Handler.__init__(self)

    @property
    def stream(self):  # type: ignore[no-untyped-def]
        return sys.stdout


def _level() -> int:
    level = logging.getLevelName(config.LOG_LEVEL.upper())
    return level if isinstance(level, int) else logging.INFO


def uvicorn_level() -> str:
    """``MATTSTASH_LOG_LEVEL`` as a name uvicorn accepts.

    Python's level names include ``WARN`` and ``FATAL`` (and an unknown name falls back to INFO for the app), but
    uvicorn raises ``KeyError`` for anything outside its own list, which would stop the server at startup.
    """
    level = _level()
    for threshold, name in ((logging.CRITICAL, "critical"), (logging.ERROR, "error"), (logging.WARNING, "warning")):
        if level >= threshold:
            return name
    return "info" if level >= logging.INFO else "debug"


def configure_logging() -> None:
    """Attach the handlers to the server's loggers (idempotent)."""
    for name, level, handler_factory, fmt in (
        ("mattstash.api", _level(), logging.StreamHandler, _FORMAT),
        (ACCESS_LOGGER, logging.INFO, _StdoutHandler, "%(message)s"),
    ):
        logger = logging.getLogger(name)
        if not any(getattr(handler, _MARKER, False) for handler in logger.handlers):
            handler = handler_factory()
            handler.setFormatter(logging.Formatter(fmt))
            setattr(handler, _MARKER, True)
            logger.addHandler(handler)
        logger.setLevel(level)
