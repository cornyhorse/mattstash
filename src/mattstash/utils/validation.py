"""
mattstash.utils.validation
--------------------------
Input validation utilities for MattStash.
"""

import os
import re
from typing import Optional

from .exceptions import InvalidCredentialError

# Maximum lengths for various fields
MAX_TITLE_LENGTH = 255
MAX_USERNAME_LENGTH = 255
MAX_URL_LENGTH = 2048
MAX_NOTES_LENGTH = 65535


ALLOW_SLASH_NAMES_ENV = "MATTSTASH_ALLOW_SLASH_NAMES"
_TRUE = frozenset({"1", "true", "yes", "on"})


def slash_names_allowed() -> bool:
    """Is writing names that contain ``/`` enabled (``MATTSTASH_ALLOW_SLASH_NAMES=true``)? Read on every call."""
    return os.environ.get(ALLOW_SLASH_NAMES_ENV, "").strip().lower() in _TRUE


def slash_name_problem(name: str) -> Optional[str]:
    """Why ``name`` (which contains ``/``) is not a valid slash name, or ``None``.

    ``/`` separates segments: a name must not start or end with ``/``, contain ``//``, or have a ``.``/``..`` segment.
    """
    if name.startswith("/") or name.endswith("/"):
        return "must not start or end with '/'"
    if "//" in name:
        return "must not contain '//'"
    if any(part in (".", "..") for part in name.split("/")):
        return "must not have a '.' or '..' segment"
    return None


def validate_credential_title(title: str, *, allow_slash: Optional[bool] = None) -> None:
    """
    Validate a credential title for security and compatibility.

    ``allow_slash`` defaults to the ``MATTSTASH_ALLOW_SLASH_NAMES`` environment variable.

    Titles must:
    - Not be empty
    - Not exceed MAX_TITLE_LENGTH characters
    - Not contain backslashes, null bytes, or control characters
    - Not start with a dot (hidden file)

    Forward slashes (/) are refused unless slash names are enabled (``MATTSTASH_ALLOW_SLASH_NAMES=true`` or
    ``allow_slash=True``); use ``.`` as the separator (``myapp.db-password``). When enabled, ``/`` separates segments
    (e.g. ``cloud/hetzner/s3-key``) and the name must not start or end with ``/``, contain ``//`` or have a ``.`` or
    ``..`` segment. Only *writing* is restricted: existing entries with ``/`` can always be read, listed and deleted.

    Args:
        title: Credential title to validate

    Raises:
        InvalidCredentialError: If title is invalid
    """
    if not title or not title.strip():
        raise InvalidCredentialError("Credential title cannot be empty")

    if len(title) > MAX_TITLE_LENGTH:
        raise InvalidCredentialError(f"Credential title too long (max {MAX_TITLE_LENGTH} characters)")

    # Disallow backslashes, null bytes, and control characters.
    dangerous_chars = ["\\", "\0", "\n", "\r", "\t"]
    for char in dangerous_chars:
        if char in title:
            raise InvalidCredentialError(f"Credential title contains invalid character: {char!r}")

    # Don't allow titles starting with '.' to avoid hidden file issues
    if title.startswith("."):
        raise InvalidCredentialError("Credential title cannot start with '.'")

    if "/" in title:
        if not (slash_names_allowed() if allow_slash is None else allow_slash):
            raise InvalidCredentialError(
                "Credential title contains '/': use '.' as the separator (for example myapp.db-password), "
                f"or set {ALLOW_SLASH_NAMES_ENV}=true to allow '/' in new names"
            )
        problem = slash_name_problem(title)
        if problem:
            raise InvalidCredentialError(f"Credential title {problem}")


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
        raise InvalidCredentialError(f"Username too long (max {MAX_USERNAME_LENGTH} characters)")


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
        raise InvalidCredentialError(f"URL too long (max {MAX_URL_LENGTH} characters)")

    # Allow flexible URL formats:
    # - Full URLs: https://example.com
    # - Host:port pairs: localhost:5432
    # - Simple hostnames: localhost
    # Just do basic validation - no dangerous characters
    dangerous_chars = ["\0", "\n", "\r", "\t"]
    for char in dangerous_chars:
        if char in url:
            raise InvalidCredentialError(f"URL contains invalid character: {char!r}")


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
        raise InvalidCredentialError(f"Notes too long (max {MAX_NOTES_LENGTH} characters)")


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
    message = re.sub(r"/[\w/.-]+\.kdbx", "<database>", message)

    # Redact absolute paths (Windows-style)
    message = re.sub(r"[A-Za-z]:\\[\w\\.-]+\.kdbx", "<database>", message)

    return message


def validate_lookup_title(title: str) -> None:
    """
    Light validation for titles used to *look up* or delete existing entries.

    Deliberately much looser than :func:`validate_credential_title`: databases created by
    other KeePass tools can hold titles with slashes, spaces, leading dots and so on, and
    lookups are exact string comparisons (no query language), so such titles are safe.
    """
    if not isinstance(title, str) or not title:
        raise InvalidCredentialError("Credential title cannot be empty")
    if len(title) > MAX_TITLE_LENGTH:
        raise InvalidCredentialError(f"Credential title too long (max {MAX_TITLE_LENGTH} characters)")
    if "\0" in title:
        raise InvalidCredentialError("Credential title contains invalid character: '\\x00'")


def api_key_problem(key: str) -> Optional[str]:
    """Why ``key`` cannot be sent as an ``X-API-Key`` header, or ``None`` if it can. Never contains the key.

    Keys are printable ASCII (an inner space is allowed: the server accepts it in ``MATTSTASH_API_KEY`` and JSON
    policies). Control characters, non-ASCII text and a leading/trailing space are not: a stray newline from a
    Kubernetes Secret or an ``echo`` is the typical culprit, and callers strip surrounding whitespace first.
    """
    if not key:
        return "the API key is empty"
    if key != key.strip() or not all(0x20 <= ord(ch) <= 0x7E for ch in key):
        return (
            "the API key contains control or non-ASCII characters, or leading/trailing whitespace "
            "(a trailing newline or a byte-order mark in the file or variable?)"
        )
    return None
