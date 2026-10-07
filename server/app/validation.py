"""Shared request validation helpers."""

import re

from fastapi import HTTPException, status

MAX_NAME_LENGTH = 255
# Letters, digits, '_', '.', '-' ; must not start with '.'. fullmatch + ASCII: no newline/unicode tricks.
_NAME_RE = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*", re.ASCII)
_PREFIX_RE = re.compile(r"[A-Za-z0-9_.-]*", re.ASCII)


def is_valid_name(name: str) -> bool:
    return 0 < len(name) <= MAX_NAME_LENGTH and _NAME_RE.fullmatch(name) is not None


def is_valid_prefix(prefix: str) -> bool:
    return len(prefix) <= MAX_NAME_LENGTH and _PREFIX_RE.fullmatch(prefix) is not None


def require_valid_name(name: str) -> None:
    """Raise 400 unless ``name`` is a legal credential name."""
    if not is_valid_name(name):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid credential name")


def require_valid_prefix(prefix: str) -> None:
    if not is_valid_prefix(prefix):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid prefix")
