"""
mattstash.cli.handlers.get
--------------------------
Handler for the get command.
"""

import json
from argparse import Namespace

from .base import BaseHandler
from ...models.credential import serialize_credential
from ...module_functions import get


class GetHandler(BaseHandler):
    """Handler for the get command."""

    def handle(self, args: Namespace) -> int:
        """Handle the get command."""
        c = get(args.title, path=args.path, password=args.password, show_password=args.show_password)
        if not c:
            self.error(f"not found: {args.title}")
            return 2

        if args.json:
            if isinstance(c, dict):
                # simple-secret mode already respects --show-password via get(show_password=...)
                print(json.dumps(c, indent=2))
            else:
                print(json.dumps(serialize_credential(c, show_password=args.show_password), indent=2))
        else:
            if isinstance(c, dict):
                print(f"{c['name']}")
                print(f"  value: {c['value']}")
            else:
                pwd_disp = c.password if args.show_password else ("*****" if c.password else None)
                print(f"{c.credential_name}")
                print(f"  username: {c.username}")
                print(f"  password: {pwd_disp}")
                print(f"  url:      {c.url}")
                print(f"  tags:     {', '.join(c.tags) if c.tags else ''}")
                if c.notes:
                    print("  notes/comments:")
                    for line in (c.notes or '').splitlines():
                        print(f"    {line}")
        return 0
