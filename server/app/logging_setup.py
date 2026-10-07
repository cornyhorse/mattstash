"""Logging for the server process.

``uvicorn`` only configures its own loggers, so without this the access log (with key ids) and the audit trail
would never be emitted by a real deployment. Both go to stderr with a timestamp:

* ``mattstash.api``   - access log and operational messages, level from ``MATTSTASH_LOG_LEVEL`` (default info);
* ``mattstash.audit`` - who did what to which credential. **Always INFO**: the audit trail is not optional and
  is not silenced by ``MATTSTASH_LOG_LEVEL=warning``.
"""

import logging

from .config import config

_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
_MARKER = "_mattstash_server_handler"


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
    """Attach stderr handlers to the server's loggers (idempotent)."""
    for name, level in (("mattstash.api", _level()), ("mattstash.audit", logging.INFO)):
        logger = logging.getLogger(name)
        if not any(getattr(handler, _MARKER, False) for handler in logger.handlers):
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter(_FORMAT))
            setattr(handler, _MARKER, True)
            logger.addHandler(handler)
        logger.setLevel(level)
