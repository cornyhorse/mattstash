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
        # Check if server mode
        if self.is_server_mode(args):
            return self._handle_server_mode(args)
        
        # Local mode
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
    
    def _handle_server_mode(self, args: Namespace) -> int:
        """Handle list command in server mode."""
        try:
            client = self.get_server_client(args)
            if client is None:
                return 1
            creds = client.list(show_password=args.show_password)
            
            if args.json:
                print(json.dumps(creds, indent=2))
            else:
                for c in creds:
                    pwd_disp = c.get('password', '*****')
                    notes_snippet = ""
                    if c.get('notes'):
                        snippet = c['notes'].strip().splitlines()[0]
                        notes_snippet = f" notes={snippet!r}"
                    print(
                        f"- {c.get('name', 'unknown')} user={c.get('username', '')!r} url={c.get('url', '')!r} pwd={pwd_disp!r}{notes_snippet}")
            return 0
        except Exception as e:
            self.error(f"Server error: {str(e)}")
            return 1


class KeysHandler(BaseHandler):
    """Handler for the keys command."""

    def handle(self, args: Namespace) -> int:
        """Handle the keys command."""
        # Check if server mode
        if self.is_server_mode(args):
            return self._handle_server_mode(args)
        
        # Local mode
        creds = list_creds(path=args.path, password=args.password, show_password=args.show_password)
        titles = [c.credential_name for c in creds]
        if args.json:
            print(json.dumps(titles, indent=2))
        else:
            for t in titles:
                print(t)
        return 0
    
    def _handle_server_mode(self, args: Namespace) -> int:
        """Handle keys command in server mode."""
        try:
            client = self.get_server_client(args)
            if client is None:
                return 1
            creds = client.list(show_password=False)
            titles = [c.get('name', '') for c in creds]
            
            if args.json:
                print(json.dumps(titles, indent=2))
            else:
                for t in titles:
                    print(t)
            return 0
        except Exception as e:
            self.error(f"Server error: {str(e)}")
            return 1
