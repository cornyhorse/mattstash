"""
mattstash.cli.handlers.get
--------------------------
Handler for the get command.
"""

import json
import sys
from argparse import Namespace
from typing import Optional

from ...models.credential import serialize_credential
from ...module_functions import get
from .. import exit_codes
from .base import BaseHandler

#: Fields selectable with ``get --raw --field``.
RAW_FIELDS = ("password", "username", "url", "notes")


class GetHandler(BaseHandler):
    """Handler for the get command."""

    def handle(self, args: Namespace) -> int:
        """Handle the get command."""
        raw = self.flag(args, "raw")
        field = self.opt(args, "field", str)
        if field is not None and not raw:
            self.error("--field requires --raw")
            return exit_codes.ERROR
        if field is not None and field not in RAW_FIELDS:
            self.error(f"--field must be one of {', '.join(RAW_FIELDS)}")
            return exit_codes.ERROR
        if raw and self.flag(args, "json"):
            self.error("--raw and --json are mutually exclusive")
            return exit_codes.ERROR

        # Check if server mode
        if self.is_server_mode(args):
            return self._handle_server_mode(args)

        if raw:
            return self._handle_raw(args, field or "password")

        # Local mode
        c = get(
            args.title,
            path=args.path,
            password=args.password,
            show_password=args.show_password,
            version=getattr(args, "version", None),
        )
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
                    for line in (c.notes or "").splitlines():
                        print(f"    {line}")
        return 0

    # ---- --raw: scripting output -------------------------------------------------

    def _emit_raw(self, value: Optional[str], title: str, field: str) -> int:
        """Write exactly ``value`` + newline to stdout (the only thing --raw ever prints there)."""
        if not value:
            self.error(f"{title}: field '{field}' is empty")
            return exit_codes.NOT_FOUND
        sys.stdout.write(value + "\n")
        sys.stdout.flush()
        return exit_codes.OK

    def _handle_raw(self, args: Namespace, field: str) -> int:
        """``get --raw``: print only the (unmasked) secret or the selected field of a full credential."""
        c = get(
            args.title,
            path=args.path,
            password=args.password,
            show_password=True,
            version=self.opt(args, "version", int),
        )
        if not c:
            self.error(f"not found: {args.title}")
            return exit_codes.NOT_FOUND
        if isinstance(c, dict):
            # Simple secret: it only has a value (the password field).
            if field != "password":
                self.error(f"{args.title} is a simple secret: it only has a 'password' (value), not '{field}'")
                return exit_codes.ERROR
            return self._emit_raw(c.get("value"), args.title, field)
        return self._emit_raw(getattr(c, field), args.title, field)

    def _handle_raw_server(self, args: Namespace, field: str) -> int:
        try:
            client = self.get_server_client(args)
            if client is None:
                return exit_codes.ERROR
            result = client.get(args.title, show_password=True, version=self.opt(args, "version", int))
            if not result:
                self.error(f"not found: {args.title}")
                return exit_codes.NOT_FOUND
            value = result.get(field)
            return self._emit_raw(value if isinstance(value, str) else None, args.title, field)
        except Exception as e:
            self.error(f"Server error: {e!s}")
            return exit_codes.ERROR

    def _handle_server_mode(self, args: Namespace) -> int:
        """Handle get command in server mode."""
        if self.flag(args, "raw"):
            return self._handle_raw_server(args, self.opt(args, "field", str) or "password")
        try:
            client = self.get_server_client(args)
            if client is None:
                return 1
            result = client.get(args.title, show_password=args.show_password, version=getattr(args, "version", None))

            if not result:
                self.error(f"not found: {args.title}")
                return 2

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"{result.get('name', args.title)}")
                if result.get("username"):
                    print(f"  username: {result.get('username')}")
                if result.get("password"):
                    pwd_disp = result["password"] if args.show_password else "*****"
                    print(f"  password: {pwd_disp}")
                if result.get("url"):
                    print(f"  url:      {result.get('url')}")
                if result.get("notes"):
                    print("  notes/comments:")
                    for line in result["notes"].splitlines():
                        print(f"    {line}")

            return 0

        except Exception as e:
            self.error(f"Server error: {e!s}")
            return 1
