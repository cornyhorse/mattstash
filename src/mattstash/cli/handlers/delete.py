"""
mattstash.cli.handlers.delete
-----------------------------
Handler for the delete command.
"""

from argparse import Namespace
from typing import Optional

from ...models.config import config
from ...module_functions import delete
from .. import exit_codes
from .base import BaseHandler


def _label(title: str, version: Optional[int]) -> str:
    return title if version is None else f"{title}@{str(version).zfill(config.version_pad_width)}"


class DeleteHandler(BaseHandler):
    """Handler for the delete command."""

    def handle(self, args: Namespace) -> int:
        """Handle the delete command (all versions, or only ``--version N``)."""
        version = self.opt(args, "version", int)

        # Check if server mode
        if self.is_server_mode(args):
            return self._handle_server_mode(args, version)

        # Local mode
        ok = delete(args.title, path=args.path, password=args.password, version=version)
        if ok:
            print(f"{_label(args.title, version)}: deleted")
            return exit_codes.OK
        self.error(f"not found: {_label(args.title, version)}")
        return exit_codes.NOT_FOUND

    def _handle_server_mode(self, args: Namespace, version: Optional[int]) -> int:
        """Handle delete command in server mode."""
        try:
            client = self.get_server_client(args)
            if client is None:
                return exit_codes.ERROR
            ok = client.delete(args.title, version=version)

            if ok:
                print(f"{_label(args.title, version)}: deleted")
                return exit_codes.OK
            else:
                self.error(f"not found: {_label(args.title, version)}")
                return exit_codes.NOT_FOUND
        except Exception as e:
            self.error(f"Server error: {e!s}")
            return exit_codes.ERROR
