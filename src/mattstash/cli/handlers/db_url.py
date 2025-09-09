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
