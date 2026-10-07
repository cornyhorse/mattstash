"""
mattstash.cli.handlers.base
---------------------------
Base class for CLI command handlers.
"""

import os
from abc import ABC, abstractmethod
from argparse import Namespace
from typing import Any, Optional

from ...utils.exceptions import DatabaseAccessError, DatabaseLockError, DatabaseNotFoundError
from ...utils.logging_config import get_logger
from .. import exit_codes
from ..inputs import InputError, read_credential_env_file, read_credential_file

logger = get_logger(__name__)


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
        explicit = getattr(args, "api_key", None)
        key_file = getattr(args, "api_key_file", None)
        if explicit and key_file:
            raise InputError("--api-key and --api-key-file are mutually exclusive")
        if explicit:
            return str(explicit)
        if key_file:
            return read_credential_file("--api-key-file", key_file)
        env_key = os.environ.get("MATTSTASH_API_KEY")
        if env_key:
            return env_key
        return read_credential_env_file("MATTSTASH_API_KEY_FILE")

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

        return MattStashServerClient(args.server_url, api_key)

    def error(self, message: str) -> None:
        """Print an error message to stderr."""
        logger.error(message)

    def info(self, message: str) -> None:
        """Print an info message to stdout."""
        print(f"[mattstash] {message}")  # pragma: no cover
