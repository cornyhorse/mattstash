"""
mattstash.cli.handlers.base
---------------------------
Base class for CLI command handlers.
"""

import logging
import os
import sys
from abc import ABC, abstractmethod
from argparse import Namespace
from typing import Any, Optional, Type, TypeVar

from ...utils.exceptions import DatabaseAccessError, DatabaseLockError, DatabaseNotFoundError, ServerError
from ...utils.logging_config import get_logger
from ...utils.validation import api_key_problem
from .. import exit_codes
from ..inputs import InputError, read_credential_env_file, read_credential_file

logger = get_logger(__name__)

_T = TypeVar("_T")

#: Problems with the database itself (as opposed to a missing secret).
DB_ERRORS = (DatabaseNotFoundError, DatabaseAccessError, DatabaseLockError)


class BaseHandler(ABC):
    """Base class for all CLI command handlers."""

    def db_error(self, exc: Exception) -> int:
        """Report a database-level error and return the matching exit code."""
        self.error(str(exc))
        return exit_codes.DB_NOT_FOUND if isinstance(exc, DatabaseNotFoundError) else exit_codes.DB_ACCESS

    @abstractmethod
    def handle(self, args: Namespace) -> int:
        """
        Handle the command with the given arguments.

        Args:
            args: Parsed command line arguments

        Returns:
            Exit code (0 for success, non-zero for error)
        """
        pass

    @staticmethod
    def opt(args: Namespace, name: str, kind: Type[_T]) -> Optional[_T]:
        """The option ``name`` if it is set and of type ``kind``, else ``None``.

        Handlers are also called with hand-built namespaces (tests, embedding), so an option that is absent,
        or not of the expected type, simply counts as "not given".
        """
        value = getattr(args, name, None)
        if isinstance(value, bool) and kind is not bool:
            return None
        return value if isinstance(value, kind) else None

    @staticmethod
    def flag(args: Namespace, name: str) -> bool:
        """True only if the boolean option ``name`` is exactly ``True``."""
        return getattr(args, name, None) is True

    def is_server_mode(self, args: Namespace) -> bool:
        """Check if server mode is enabled."""
        # Check if attribute exists and has a truthy value (not None, not empty string)
        if not hasattr(args, "server_url"):
            return False
        server_url = getattr(args, "server_url", None)
        # Explicitly check for string type to avoid Mock objects being treated as truthy
        return isinstance(server_url, str) and len(server_url) > 0

    def resolve_api_key(self, args: Namespace) -> Optional[str]:
        """Server API key. Precedence: --api-key > --api-key-file > MATTSTASH_API_KEY > MATTSTASH_API_KEY_FILE.

        Raises:
            InputError: an explicitly configured key file cannot be used (never silently skipped).
        """
        explicit = self.opt(args, "api_key", str)
        key_file = self.opt(args, "api_key_file", str)
        if explicit is not None and key_file is not None:
            raise InputError("--api-key and --api-key-file are mutually exclusive")
        if explicit is not None:
            key = explicit.strip()
            if not key:
                raise InputError("--api-key was given an empty value")
        elif key_file is not None:
            if not key_file.strip():
                raise InputError("--api-key-file was given an empty path")
            key = read_credential_file("--api-key-file", key_file)
        else:
            # A Kubernetes Secret or `echo` adds a newline: keys never contain whitespace, so strip like the files do.
            key = (
                (os.environ.get("MATTSTASH_API_KEY") or "").strip()
                or read_credential_env_file("MATTSTASH_API_KEY_FILE")
                or ""
            )
        if key:
            problem = api_key_problem(key)
            if problem:
                raise InputError(problem)
        return key or None

    def get_server_client(self, args: Namespace) -> Optional[Any]:
        """Get MattStash server client if in server mode."""
        if not self.is_server_mode(args):
            return None

        from ..http_client import MattStashServerClient

        try:
            api_key = self.resolve_api_key(args)
        except InputError as exc:
            self.error(str(exc))
            return None
        if not api_key:
            self.error(
                "API key required for server mode. Use --api-key-file, --api-key, or set "
                "MATTSTASH_API_KEY_FILE / MATTSTASH_API_KEY."
            )
            return None

        try:
            return MattStashServerClient(args.server_url, api_key)
        except ServerError as exc:
            self.error(str(exc))
            return None

    def error(self, message: str) -> None:
        """Print an error message to stderr.

        Goes through the logger (so it is formatted, filterable and capturable), but never disappears: with logging
        silenced (``MATTSTASH_LOG_LEVEL=CRITICAL``) the failure explanation is written to stderr directly.
        """
        logger.error(message)
        if not logger.isEnabledFor(logging.ERROR):
            print(message, file=sys.stderr)

    def warning(self, message: str) -> None:
        """Log a warning (stderr)."""
        logger.warning(message)

    def deprecation(self, message: str) -> None:
        """Log a deprecation warning (stderr)."""
        logger.warning(f"DEPRECATED: {message}")

    def info(self, message: str) -> None:
        """Print an info message to stdout."""
        print(f"[mattstash] {message}")  # pragma: no cover
