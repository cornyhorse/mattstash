"""
mattstash.cli.handlers.rotate
-----------------------------
Handler for the rotate-password command (local database only).

The old password comes from the usual sources (--password/--db-password/--db-password-file,
KDBX_PASSWORD, KDBX_PASSWORD_FILE, sidecar); the new one from --new-password-file,
--new-password-stdin, --generate or an interactive prompt (asked twice).
"""

import getpass
import os
import secrets
import sys
from argparse import Namespace
from typing import Optional, Tuple

from ...core.mattstash import MattStash
from ...core.password_resolver import PasswordResolver
from ...utils.exceptions import SidecarUpdateError
from .. import exit_codes
from ..inputs import InputError, read_credential_file, read_stdin_line
from .base import BaseHandler


class RotatePasswordHandler(BaseHandler):
    """Handler for ``mattstash rotate-password``."""

    def handle(self, args: Namespace) -> int:
        """Re-key the database (after a backup, unless --no-backup) and update the sidecar if present."""
        if self.is_server_mode(args):
            self.error(
                "rotate-password is not supported in server mode: it re-keys the database file. "
                "Run it where the file lives (omit --server-url / MATTSTASH_SERVER_URL)."
            )
            return exit_codes.ERROR
        try:
            new_password, generated = self._new_password(args)
        except InputError as exc:
            self.error(str(exc))
            return exit_codes.ERROR
        if new_password is None:
            self.error(
                "No source for the new password. Use one of --new-password-file, --new-password-stdin or "
                "--generate, or run interactively to be prompted."
            )
            return exit_codes.ERROR

        stash = MattStash(path=args.path, password=args.password)
        sidecar = PasswordResolver(stash.path).sidecar_path
        had_sidecar = os.path.exists(sidecar)
        sidecar_error: Optional[str] = None
        try:
            backup_path = stash.rotate_password(new_password, backup=not getattr(args, "no_backup", False))
        except SidecarUpdateError as exc:
            # The database is re-keyed: the new password must still reach the user.
            backup_path, sidecar_error = None, str(exc)

        print(f"Master password rotated for {stash.path}")
        if backup_path:
            print(f"  Backup (opens with the OLD password; delete it once the new one is verified): {backup_path}")
        if sidecar_error:
            self.error(sidecar_error)
        elif had_sidecar:
            print(f"  Sidecar password file updated: {sidecar}")
        if generated:
            print(f"  Generated new master password (shown once, store it safely): {new_password}")
        self._warn_stale_environment()
        return exit_codes.ERROR if sidecar_error else exit_codes.OK

    # ---- helpers ------------------------------------------------------------------

    def _warn_stale_environment(self) -> None:
        for name in ("KDBX_PASSWORD", "KDBX_PASSWORD_FILE"):
            if os.environ.get(name):
                self.error(
                    f"warning: {name} is set and still provides the OLD password: update it, and restart anything "
                    "(such as the server) that reads it"
                )

    def _new_password(self, args: Namespace) -> Tuple[Optional[str], bool]:
        """``(password, generated)``; ``(None, False)`` if no source was given and we cannot prompt."""
        if getattr(args, "generate", False):
            return secrets.token_urlsafe(32), True
        password_file = getattr(args, "new_password_file", None)
        if password_file:
            return read_credential_file("--new-password-file", password_file), False
        if getattr(args, "new_password_stdin", False):
            return read_stdin_line("--new-password-stdin"), False
        if sys.stdin.isatty():
            first = getpass.getpass("New master password: ")
            if not first:
                raise InputError("The new password cannot be empty")
            if getpass.getpass("Repeat new master password: ") != first:
                raise InputError("The passwords do not match")
            return first, False
        return None, False
