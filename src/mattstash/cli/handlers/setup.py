"""
mattstash.cli.handlers.setup
----------------------------
Handler for the setup command: the only place a database is ever created.
"""

import getpass
import os
import sys
from argparse import Namespace
from typing import Optional

from ...core.bootstrap import DatabaseBootstrapper
from ...core.password_resolver import PasswordResolver, read_password_file
from ...models.config import config
from ...utils.exceptions import DatabaseExistsError, MattStashError
from .. import exit_codes
from .base import BaseHandler


class SetupHandler(BaseHandler):
    """Handler for the setup command."""

    def handle(self, args: Namespace) -> int:
        """Handle the setup command."""
        db_path = os.path.expanduser(getattr(args, "path", None) or config.default_db_path)
        bootstrapper = DatabaseBootstrapper(db_path)
        force = bool(getattr(args, "force", False))
        existing = bootstrapper.existing_files()

        if existing and not force:
            self.error("Setup aborted - files already exist:")
            for path in existing:
                print(f"  {path}")
            self.error("Use --force to replace them (existing files are backed up first)")
            return exit_codes.WOULD_OVERWRITE

        if existing and not self._confirm_replace(existing, bool(getattr(args, "yes", False))):
            return exit_codes.WOULD_OVERWRITE

        try:
            password = self._password_from_args(args, db_path)
        except (OSError, ValueError, MattStashError) as exc:
            self.error(f"Setup failed: {exc}")
            return exit_codes.ERROR
        sidecar = bool(getattr(args, "sidecar", False))
        generate = bool(getattr(args, "generate", False))

        if password is None and not sidecar and not generate:
            password = self._prompt_password()
            if password is None:
                self.error(
                    "No master password source. Use one of: --sidecar, --generate, --password-file, "
                    "--password-stdin, the KDBX_PASSWORD / KDBX_PASSWORD_FILE environment variables, "
                    "or run interactively to be prompted."
                )
                return exit_codes.ERROR

        try:
            info = bootstrapper.create(
                password,
                sidecar=sidecar,
                force=force,
                backup=not getattr(args, "no_backup", False),
            )
        except DatabaseExistsError as exc:
            self.error(str(exc))
            return exit_codes.WOULD_OVERWRITE
        except MattStashError as exc:
            self.error(f"Setup failed: {exc}")
            return exit_codes.ERROR

        self.info("Setup complete!")
        print(f"  Database created: {info.db_path}")
        if info.sidecar_path:
            print(f"  Password file created: {info.sidecar_path}")
            print("  Note: the password is stored next to the database; anyone who can read this directory can")
            print("        open it. Prefer an operator-supplied password (KDBX_PASSWORD_FILE) for services.")
        for backup in info.backups:
            print(f"  Backed up previous file: {backup}")
        if info.generated and not info.sidecar_path:
            print(f"  Generated master password (shown once, store it safely): {info.password}")
        return exit_codes.OK

    # ---- helpers ------------------------------------------------------------

    def _confirm_replace(self, existing: list[str], assume_yes: bool) -> bool:
        if assume_yes:
            return True
        if not sys.stdin.isatty():
            self.error("Refusing to replace existing files non-interactively; pass --yes to confirm.")
            return False
        print("This will REPLACE the following (backups are written first):")
        for path in existing:
            print(f"  {path}")
        try:
            answer = input("Type 'yes' to continue: ")
        except EOFError:
            return False
        return answer.strip().lower() == "yes"

    def _password_from_args(self, args: Namespace, db_path: str) -> Optional[str]:
        """Explicit password sources, most specific first. Returns None if none was given."""
        if getattr(args, "password_stdin", False):
            line = sys.stdin.readline().rstrip("\r\n")
            if not line:
                raise ValueError("no password received on stdin")
            return line
        password_file = getattr(args, "password_file", None)
        if password_file:
            password = read_password_file(os.path.expanduser(password_file))
            if not password:
                raise ValueError(f"password file {password_file} is empty")
            return password
        explicit = getattr(args, "password", None)
        if explicit:
            self.error("warning: --password on the command line is visible to other users (ps, shell history)")
            return str(explicit)
        # KDBX_PASSWORD / KDBX_PASSWORD_FILE (the same sources every other command opens the DB with)
        return PasswordResolver(db_path).resolve_from_environment()

    def _prompt_password(self) -> Optional[str]:
        if not sys.stdin.isatty():
            return None
        first = getpass.getpass("New master password: ")
        if not first:
            self.error("Password cannot be empty")
            return None
        if getpass.getpass("Repeat master password: ") != first:
            self.error("Passwords do not match")
            return None
        return first
