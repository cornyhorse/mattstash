"""
mattstash.cli.handlers.list
---------------------------
Handler for the list and keys commands.
"""

import json
from argparse import Namespace

from .base import BaseHandler
from ...models.credential import serialize_credential
from ...module_functions import list_creds


class ListHandler(BaseHandler):
    """Handler for the list command."""

    def handle(self, args: Namespace) -> int:
        """Handle the list command."""
        creds = list_creds(path=args.path, password=args.password, show_password=args.show_password)
        if args.json:
            payload = [serialize_credential(c, show_password=args.show_password) for c in creds]
            print(json.dumps(payload, indent=2))
        else:
            for c in creds:
                pwd_disp = c.password if args.show_password else ("*****" if c.password else None)
                notes_snippet = ""
                if c.notes and c.notes.strip():
                    snippet = c.notes.strip().splitlines()[0]
                    notes_snippet = f" notes={snippet!r}"
                print(
                    f"- {c.credential_name} user={c.username!r} url={c.url!r} pwd={pwd_disp!r} tags={c.tags}{notes_snippet}")
        return 0


class KeysHandler(BaseHandler):
    """Handler for the keys command."""

    def handle(self, args: Namespace) -> int:
        """Handle the keys command."""
        creds = list_creds(path=args.path, password=args.password, show_password=args.show_password)
        titles = [c.credential_name for c in creds]
        if args.json:
            print(json.dumps(titles, indent=2))
        else:
            for t in titles:
                print(t)
        return 0
