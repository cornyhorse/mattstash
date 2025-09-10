"""
mattstash.cli.handlers.put
--------------------------
Handler for the put command.
"""

import json
from argparse import Namespace

from .base import BaseHandler
from ...models.credential import serialize_credential
from ...module_functions import put


class PutHandler(BaseHandler):
    """Handler for the put command."""

    def handle(self, args: Namespace) -> int:
        """Handle the put command."""
        if args.value is not None and not args.fields:
            # Simple value mode (credstash-like)
            result = put(
                args.title,
                path=args.path,
                db_password=args.password,
                value=args.value,
                notes=args.notes,
                comment=args.comment,
                tags=args.tags,
            )
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                if isinstance(result, dict):
                    print(f"{result['name']}: {result['value']}")
                else:
                    print(f"{args.title}: OK")
            return 0

        # Fields mode - use CLI --password as credential password, not database password
        # Database password comes from sidecar file or environment variable
        result = put(
            args.title,
            path=args.path,
            db_password=None,  # Let it resolve from sidecar/.env normally
            username=args.username,
            password=args.password,  # This is the credential password to store
            url=args.url,
            notes=args.notes,
            comment=args.comment,
            tags=args.tags,
        )
        if args.json:
            if isinstance(result, dict):
                print(json.dumps(result, indent=2))
            else:
                print(json.dumps(serialize_credential(result, show_password=False), indent=2))
        else:
            print(f"{args.title}: OK")
        return 0
