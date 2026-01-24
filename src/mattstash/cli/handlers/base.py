"""
mattstash.cli.handlers.base
---------------------------
Base class for CLI command handlers.
"""

import sys
from abc import ABC, abstractmethod
from argparse import Namespace
from typing import Any

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

    def error(self, message: str) -> None:
        """Print an error message to stderr."""
        logger.error(message)

    def info(self, message: str) -> None:
        """Print an info message to stdout."""
        print(f"[mattstash] {message}")  # pragma: no cover
