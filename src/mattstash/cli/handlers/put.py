"""
mattstash.cli.handlers.put
--------------------------
Handler for the put command.
"""

import json
import sys
from argparse import Namespace

from .base import BaseHandler
from ...models.credential import serialize_credential
from ...module_functions import put


class PutHandler(BaseHandler):
    """Handler for the put command."""

    def handle(self, args: Namespace) -> int:
        """Handle the put command."""
        # Auto-detect fields mode when field-specific args are provided
        has_field_args = any([
            getattr(args, 'username', None),
            getattr(args, 'url', None),
        ])
        if not args.value and not args.fields and has_field_args:
            args.fields = True

        # Require either --value or --fields (explicitly or auto-detected)
        if not args.value and not args.fields:
            print("Error: one of --value or --fields is required "
                  "(--fields is auto-inferred when --username, --password, or --url is provided)",
                  file=sys.stderr)
            return 1

        # Check if server mode
        if self.is_server_mode(args):
            return self._handle_server_mode(args)
        
        # Local mode
        try:
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
                if result is None:
                    print("Error: Failed to store credential (database may be inaccessible)", file=sys.stderr)
                    return 1
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
            if result is None:
                print("Error: Failed to store credential (database may be inaccessible)", file=sys.stderr)
                return 1
            if args.json:
                if isinstance(result, dict):
                    print(json.dumps(result, indent=2))
                else:
                    print(json.dumps(serialize_credential(result, show_password=False), indent=2))
            else:
                print(f"{args.title}: OK")
            return 0
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    def _handle_server_mode(self, args: Namespace) -> int:
        """Handle put command in server mode."""
        try:
            client = self.get_server_client(args)
            
            # Determine if simple value mode or fields mode
            kwargs = {}
            if args.value is not None:
                kwargs['value'] = args.value
            else:
                if args.username:
                    kwargs['username'] = args.username
                if args.password:
                    kwargs['password'] = args.password
                if args.url:
                    kwargs['url'] = args.url
            
            if args.notes:
                kwargs['notes'] = args.notes
            if args.comment:
                kwargs['comment'] = args.comment
            if args.tags:
                kwargs['tags'] = args.tags
            
            result = client.put(args.title, **kwargs)
            
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"{args.title}: OK")
            
            return 0
            
        except Exception as e:
            self.error(f"Server error: {str(e)}")
            return 1
