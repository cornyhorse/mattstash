"""
mattstash.cli.handlers.base
---------------------------
Base class for CLI command handlers.
"""

from abc import ABC, abstractmethod
from argparse import Namespace
from typing import Any, Optional

from ...utils.logging_config import get_logger

logger = get_logger(__name__)


class BaseHandler(ABC):
    """Base class for all CLI command handlers."""

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

    def get_server_client(self, args: Namespace) -> Optional[Any]:
        """Get MattStash server client if in server mode."""
        if not self.is_server_mode(args):
            return None

        from ..http_client import MattStashServerClient

        if not args.api_key:
            self.error("API key required for server mode. Use --api-key or set MATTSTASH_API_KEY environment variable.")
            return None

        return MattStashServerClient(args.server_url, args.api_key)

    def error(self, message: str) -> None:
        """Print an error message to stderr."""
        logger.error(message)

    def info(self, message: str) -> None:
        """Print an info message to stdout."""
        print(f"[mattstash] {message}")  # pragma: no cover
