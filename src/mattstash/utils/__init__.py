"""
mattstash.utils
---------------
Utility functions and classes.
"""

from .exceptions import MattStashError, DatabaseNotFoundError, DatabaseAccessError, CredentialNotFoundError
from .logging_config import get_logger, configure_logging, security_warning
from .validation import (
    validate_credential_title,
    validate_username,
    validate_url,
    validate_notes,
    sanitize_error_message,
)

__all__ = [
    'MattStashError',
    'DatabaseNotFoundError',
    'DatabaseAccessError',
    'CredentialNotFoundError',
    'get_logger',
    'configure_logging',
    'security_warning',
    'validate_credential_title',
    'validate_username',
    'validate_url',
    'validate_notes',
    'sanitize_error_message',
]
