"""Shared request validation helpers."""

import re

from fastapi import HTTPException, Request, status
from mattstash.utils.validation import slash_name_problem
from starlette.convertors import PathConvertor, register_url_convertor

from .config import config

MAX_NAME_LENGTH = 255
# Letters, digits, '_', '.', '-' ; must not start with '.'. fullmatch + ASCII: no newline/unicode tricks.
_NAME_RE = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*", re.ASCII)
_PREFIX_RE = re.compile(r"[A-Za-z0-9_.-]*", re.ASCII)
# With MATTSTASH_ALLOW_SLASH_NAMES: the same characters plus '/'. The segment rules are checked separately.
_SLASH_NAME_RE = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_./-]*", re.ASCII)
_SLASH_PREFIX_RE = re.compile(r"[A-Za-z0-9_./-]*", re.ASCII)


class _NamePathConvertor(PathConvertor):
    """``{name:namepath}``: like ``{name:path}`` (may contain ``/``) but never empty, so ``/credentials/`` still
    redirects to ``/credentials`` instead of being a credential with no name."""

    regex = r"[\s\S]+"  # newlines included: they are matched here and refused (400) by the name rules


register_url_convertor("namepath", _NamePathConvertor())


def is_valid_name(name: str) -> bool:
    """A credential name this server can address. ``/`` is only legal when ``ALLOW_SLASH_NAMES`` is on."""
    if not 0 < len(name) <= MAX_NAME_LENGTH:
        return False
    if "/" in name:
        return config.ALLOW_SLASH_NAMES and _SLASH_NAME_RE.fullmatch(name) is not None and not slash_name_problem(name)
    return _NAME_RE.fullmatch(name) is not None


def is_valid_prefix(prefix: str) -> bool:
    pattern = _SLASH_PREFIX_RE if config.ALLOW_SLASH_NAMES else _PREFIX_RE
    return len(prefix) <= MAX_NAME_LENGTH and pattern.fullmatch(prefix) is not None


def require_valid_name(name: str) -> None:
    """Raise 400 unless ``name`` is a legal credential name."""
    if not is_valid_name(name):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid credential name")


def require_slash_names_enabled(request: Request) -> None:
    """Route dependency for the ``{name:path}`` routes: a name with ``/`` is a plain 404 unless the server allows
    slash names, exactly as before those routes existed (no single-segment route matched it)."""
    if "/" in str(request.path_params.get("name", "")) and not config.ALLOW_SLASH_NAMES:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


def require_valid_prefix(prefix: str) -> None:
    if not is_valid_prefix(prefix):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid prefix")
