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
        # Check if server mode
        if self.is_server_mode(args):
            return self._handle_server_mode(args)
        
        # Local mode
        vers = list_versions(args.title, path=args.path, password=args.password)
        if args.json:
            print(json.dumps(vers, indent=2))
        else:
            for v in vers:
                print(v)
        return 0
    
    def _handle_server_mode(self, args: Namespace) -> int:
        """Handle versions command in server mode."""
        try:
            client = self.get_server_client(args)
            if client is None:
                return 1
            vers = client.versions(args.title)
            
            if not vers:
                self.error(f"not found: {args.title}")
                return 2
            
            if args.json:
                print(json.dumps(vers, indent=2))
            else:
                for v in vers:
                    print(v)
            return 0
        except Exception as e:
            self.error(f"Server error: {str(e)}")
            return 1
