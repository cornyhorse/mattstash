"""
mattstash.utils.validation
--------------------------
Input validation utilities for MattStash.
"""

import re
from typing import Optional
from .exceptions import InvalidCredentialError


# Maximum lengths for various fields
MAX_TITLE_LENGTH = 255
MAX_USERNAME_LENGTH = 255
MAX_URL_LENGTH = 2048
MAX_NOTES_LENGTH = 65535


def validate_credential_title(title: str) -> None:
    """
    Validate a credential title for security and compatibility.
    
    Titles must:
    - Not be empty
    - Not exceed MAX_TITLE_LENGTH characters
    - Not contain path separators or other dangerous characters
    - Not start with a dot (hidden file)
    
    Args:
        title: Credential title to validate
        
    Raises:
        InvalidCredentialError: If title is invalid
    """
    if not title or not title.strip():
        raise InvalidCredentialError("Credential title cannot be empty")
    
    if len(title) > MAX_TITLE_LENGTH:
        raise InvalidCredentialError(
            f"Credential title too long (max {MAX_TITLE_LENGTH} characters)"
        )
    
    # Disallow path separators and other dangerous characters
    dangerous_chars = ['/', '\\', '\0', '\n', '\r', '\t']
    for char in dangerous_chars:
        if char in title:
            raise InvalidCredentialError(
                f"Credential title contains invalid character: {repr(char)}"
            )
    
    # Don't allow titles starting with '.' to avoid hidden file issues
    if title.startswith('.'):
        raise InvalidCredentialError(
            "Credential title cannot start with '.'"
        )


def validate_username(username: Optional[str]) -> None:
    """
    Validate a username field.
    
    Args:
        username: Username to validate
        
    Raises:
        InvalidCredentialError: If username is invalid
    """
    if username is None:
        return
    
    if len(username) > MAX_USERNAME_LENGTH:
        raise InvalidCredentialError(
            f"Username too long (max {MAX_USERNAME_LENGTH} characters)"
        )


def validate_url(url: Optional[str]) -> None:
    """
    Validate a URL field.
    
    The URL field in KeePass can contain either:
    1. Full URLs with scheme (https://example.com)
    2. Host:port pairs for database connections (localhost:5432)
    3. Simple hostnames (localhost)
    
    Args:
        url: URL to validate
        
    Raises:
        InvalidCredentialError: If URL is invalid
    """
    if url is None or not url.strip():
        return
    
    if len(url) > MAX_URL_LENGTH:
        raise InvalidCredentialError(
            f"URL too long (max {MAX_URL_LENGTH} characters)"
        )
    
    # Allow flexible URL formats:
    # - Full URLs: https://example.com
    # - Host:port pairs: localhost:5432
    # - Simple hostnames: localhost
    # Just do basic validation - no dangerous characters
    dangerous_chars = ['\0', '\n', '\r', '\t']
    for char in dangerous_chars:
        if char in url:
            raise InvalidCredentialError(
                f"URL contains invalid character: {repr(char)}"
            )


def validate_notes(notes: Optional[str]) -> None:
    """
    Validate notes field.
    
    Args:
        notes: Notes to validate
        
    Raises:
        InvalidCredentialError: If notes are invalid
    """
    if notes is None:
        return
    
    if len(notes) > MAX_NOTES_LENGTH:
        raise InvalidCredentialError(
            f"Notes too long (max {MAX_NOTES_LENGTH} characters)"
        )


def sanitize_error_message(error: Exception, db_path: Optional[str] = None) -> str:
    """
    Sanitize error messages to avoid exposing internal paths or sensitive information.
    
    Args:
        error: Original exception
        db_path: Database path to redact from message
        
    Returns:
        Sanitized error message safe for display to users
    """
    message = str(error)
    
    # Redact database paths
    if db_path:
        message = message.replace(db_path, "<database>")
    
    # Redact common sensitive paths
    import os
    home_dir = os.path.expanduser("~")
    if home_dir in message:
        message = message.replace(home_dir, "~")
    
    # Redact absolute paths (Unix-style)
    message = re.sub(r'/[\w/.-]+\.kdbx', '<database>', message)
    
    # Redact absolute paths (Windows-style)
    message = re.sub(r'[A-Za-z]:\\[\w\\.-]+\.kdbx', '<database>', message)
    
    return message
