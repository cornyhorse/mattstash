"""
mattstash.cli.handlers.db_url
-----------------------------
Handler for the db-url command.
"""

from argparse import Namespace

from .base import BaseHandler
from ...module_functions import get_db_url


class DbUrlHandler(BaseHandler):
    """Handler for the db-url command."""

    def handle(self, args: Namespace) -> int:
        """Handle the db-url command."""
        # Check if server mode
        if self.is_server_mode(args):
            return self._handle_server_mode(args)
        
        # Local mode
        try:
            url = get_db_url(
                args.title,
                path=args.path,
                password=args.password,
                driver=args.driver,
                mask_password=args.mask_password,
                mask_style="omit",  # CLI masks by omission (no placeholder)
                database=args.database,
            )
            print(url)
            return 0
        except Exception as e:
            self.error(f"failed to build DB URL: {e}")
            return 5
    
    def _handle_server_mode(self, args: Namespace) -> int:
        """Handle db-url command in server mode."""
        try:
            client = self.get_server_client(args)
            url = client.db_url(
                args.title,
                driver=args.driver,
                database=args.database,
                mask_password=args.mask_password
            )
            print(url)
            return 0
        except Exception as e:
            self.error(f"Server error: {str(e)}")
            return 5
