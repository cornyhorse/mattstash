"""
mattstash.cli.handlers.delete
-----------------------------
Handler for the delete command.
"""

from argparse import Namespace

from .base import BaseHandler
from ...module_functions import delete


class DeleteHandler(BaseHandler):
    """Handler for the delete command."""

    def handle(self, args: Namespace) -> int:
        """Handle the delete command."""
        ok = delete(args.title, path=args.path, password=args.password)
        if ok:
            print(f"{args.title}: deleted")
            return 0
        else:
            return 2
