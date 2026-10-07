"""
mattstash.cli.handlers.prune
----------------------------
Handler for the prune command: keep only the newest N versions of a secret.
"""

from argparse import Namespace

from ...core.mattstash import MattStash
from .. import exit_codes
from .base import BaseHandler


class PruneHandler(BaseHandler):
    """Handler for the prune command (local database only)."""

    def handle(self, args: Namespace) -> int:
        """Delete all but the newest ``--keep`` versions of the secret."""
        if self.is_server_mode(args):
            self.error(
                "prune is not supported in server mode: the server API has no prune operation. "
                "Run it against the database file (omit --server-url / MATTSTASH_SERVER_URL)."
            )
            return exit_codes.ERROR
        keep = int(args.keep)
        if keep < 1:
            self.error("--keep must be at least 1")
            return exit_codes.ERROR

        stash = MattStash(path=args.path, password=args.password)
        versions = stash.list_versions(args.title)
        if not versions:
            self.error(f"not found: no versions of {args.title}")
            return exit_codes.NOT_FOUND
        deleted = stash.prune(args.title, keep)
        if not deleted:
            print(f"{args.title}: nothing to prune ({len(versions)} version(s), keeping {keep})")
            return exit_codes.OK
        print(f"{args.title}: pruned {len(deleted)} version(s), kept {len(versions) - len(deleted)}")
        for version in deleted:
            print(f"  deleted {version}")
        return exit_codes.OK
