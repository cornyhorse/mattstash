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
        log_level = os.getenv("MATTSTASH_LOG_LEVEL", "WARNING").upper()
        try:
            logger.setLevel(getattr(logging, log_level))
        except AttributeError:
            logger.setLevel(logging.WARNING)

    _logger = logger
    return logger


def configure_logging(level: str = "WARNING") -> None:
    """
    Configure logging for MattStash.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    logger = get_logger()
    try:
        logger.setLevel(getattr(logging, level.upper()))
    except AttributeError:
        logger.setLevel(logging.WARNING)


# Convenience function for security-related warnings
def security_warning(message: str) -> None:
    """
    Log a security-related warning.

    Args:
        message: Warning message
    """
    logger = get_logger()
    logger.warning(f"[SECURITY] {message}")
