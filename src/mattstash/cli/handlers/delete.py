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
        # Check if server mode
        if self.is_server_mode(args):
            return self._handle_server_mode(args)
        
        # Local mode
        ok = delete(args.title, path=args.path, password=args.password)
        if ok:
            print(f"{args.title}: deleted")
            return 0
        else:
            return 2
    
    def _handle_server_mode(self, args: Namespace) -> int:
        """Handle delete command in server mode."""
        try:
            client = self.get_server_client(args)
            if client is None:
                return 1
            ok = client.delete(args.title)
            
            if ok:
                print(f"{args.title}: deleted")
                return 0
            else:
                self.error(f"not found: {args.title}")
                return 2
        except Exception as e:
            self.error(f"Server error: {str(e)}")
            return 1
