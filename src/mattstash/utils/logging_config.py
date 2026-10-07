"""
mattstash.utils.logging_config
------------------------------
Logging configuration and utilities for MattStash.
"""

import logging
import os
import sys
from typing import Optional

# Module-level logger
_logger: Optional[logging.Logger] = None


def _parse_level(name: str) -> int:
    """A logging level from its name; anything that is not a level name (``verbose``, ``BASIC_FORMAT``) is WARNING."""
    level = logging.getLevelName(name.strip().upper())
    return level if isinstance(level, int) else logging.WARNING


def get_logger(name: str = "mattstash") -> logging.Logger:
    """
    Get a configured logger instance for MattStash.

    The logger can be controlled via the MATTSTASH_LOG_LEVEL environment variable.
    Valid values: DEBUG, INFO, WARNING, ERROR, CRITICAL
    Default: WARNING (suppresses most informational messages)

    Args:
        name: Logger name (default: "mattstash")

    Returns:
        Configured logger instance
    """
    global _logger

    if _logger is not None and _logger.name == name:
        return _logger

    logger = logging.getLogger(name)

    # Only configure if not already configured
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter("[%(name)s] %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        # Set level from environment or default to WARNING
        logger.setLevel(_parse_level(os.getenv("MATTSTASH_LOG_LEVEL", "WARNING")))

    _logger = logger
    return logger


def configure_logging(level: str = "WARNING") -> None:
    """
    Configure logging for MattStash.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    get_logger().setLevel(_parse_level(level))


# Convenience function for security-related warnings
def security_warning(message: str) -> None:
    """
    Log a security-related warning.

    Args:
        message: Warning message
    """
    logger = get_logger()
    logger.warning(f"[SECURITY] {message}")
