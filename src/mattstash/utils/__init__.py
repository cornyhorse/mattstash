"""
mattstash.utils
---------------
Utility functions and classes.
"""

from .exceptions import CredentialNotFoundError, DatabaseAccessError, DatabaseNotFoundError, MattStashError
from .logging_config import configure_logging, get_logger, security_warning
from .validation import (
    sanitize_error_message,
    validate_credential_title,
    validate_notes,
    validate_url,
    validate_username,
)

__all__ = [
    "CredentialNotFoundError",
    "DatabaseAccessError",
    "DatabaseNotFoundError",
    "MattStashError",
    "configure_logging",
    "get_logger",
    "sanitize_error_message",
    "security_warning",
    "validate_credential_title",
    "validate_notes",
    "validate_url",
    "validate_username",
]
