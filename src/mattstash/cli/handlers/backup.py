"""
mattstash.cli.handlers.backup
-----------------------------
Handler for the backup command (local database only).
"""

from argparse import Namespace

from ...core.mattstash import MattStash
from ...utils.exceptions import DatabaseExistsError
from .. import exit_codes
from .base import BaseHandler


class BackupHandler(BaseHandler):
    """Handler for ``mattstash backup [DEST] [--force]``."""

    def handle(self, args: Namespace) -> int:
        """Copy the database file consistently (under the write lock) and print the backup path."""
        if self.is_server_mode(args):
            self.error(
                "backup is not supported in server mode: it copies the database file. "
                "Run it where the file lives (omit --server-url / MATTSTASH_SERVER_URL)."
            )
            return exit_codes.ERROR
        stash = MattStash(path=self.opt(args, "path", str), password=self.opt(args, "password", str))
        try:
            dest = stash.backup(self.opt(args, "dest", str), force=self.flag(args, "force"))
        except DatabaseExistsError as exc:
            self.error(str(exc))
            return exit_codes.WOULD_OVERWRITE
        print(dest)  # the only output: easy to capture in scripts (BAK=$(mattstash backup))
        return exit_codes.OK
