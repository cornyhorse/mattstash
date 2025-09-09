"""
mattstash.cli.handlers.versions
-------------------------------
Handler for the versions command.
"""

import json
from argparse import Namespace

from .base import BaseHandler
from ...module_functions import list_versions


class VersionsHandler(BaseHandler):
    """Handler for the versions command."""

    def handle(self, args: Namespace) -> int:
        """Handle the versions command."""
        vers = list_versions(args.title, path=args.path, password=args.password)
        if args.json:
            print(json.dumps(vers, indent=2))
        else:
            for v in vers:
                print(v)
        return 0
