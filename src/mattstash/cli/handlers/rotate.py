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
from ...utils.exceptions import RekeyVerifyError, RotationIncompleteError
from .. import exit_codes
from ..inputs import InputError, read_credential_file, read_stdin_line
from .base import BaseHandler


def _read_or_none(path: str) -> Optional[str]:
    try:
        with open(path, encoding="utf-8-sig") as f:
            return f.read().strip()
    except (OSError, UnicodeDecodeError):
        return None


def _sibling_databases(db_path: str) -> list[str]:
    """Other KeePass files in the database's directory (they may rely on the same sidecar)."""
    directory = os.path.dirname(db_path)
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    own = os.path.basename(os.path.realpath(db_path))
    return sorted(n for n in names if n.endswith(".kdbx") and n not in (own, os.path.basename(db_path)))


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

        stash = MattStash(path=self.opt(args, "path", str), password=self.opt(args, "password", str))
        sidecar = PasswordResolver(stash.path).sidecar_path
        had_sidecar = os.path.lexists(sidecar)
        failure: Optional[RotationIncompleteError] = None
        backup_path: Optional[str] = None
        shown = False

        def reveal() -> None:
            # Called by the library the moment the database holds the new password -- before the sidecar swap and
            # the (slow) verification -- so that nothing after this point can lose a generated password.
            nonlocal shown
            if generated:
                self.say(f"Generated new master password (shown once, store it safely): {new_password}")
                shown = True

        try:
            backup_path = stash.rotate_password(
                new_password, backup=not self.flag(args, "no_backup"), on_rekeyed=reveal
            )
        except RotationIncompleteError as exc:
            # The database IS re-keyed: whatever else went wrong, the new password must still reach the user.
            failure, backup_path = exc, exc.backup_path
        except BaseException as exc:
            # Nothing was re-keyed (Ctrl-C included), but a backup taken before the failure should not be a secret.
            backup = getattr(exc, "backup_path", None)
            if backup:
                self.say(f"A backup made before the failure was kept: {backup}", err=True)
            raise

        if generated and not shown:
            self.say(f"Generated new master password (shown once, store it safely): {new_password}")
        lines = [f"Master password rotated for {stash.path}"] if failure is None else []
        if backup_path:
            lines.append(
                f"  Backup (opens with the OLD password; delete it once the new one is verified): {backup_path}"
            )
        if failure is None and had_sidecar:
            if _read_or_none(sidecar) == new_password:
                lines.append(f"  Sidecar password file updated: {sidecar}")
                siblings = _sibling_databases(stash.path)
                if siblings:
                    lines.append(
                        "  warning: other database files in this directory ("
                        + ", ".join(siblings)
                        + ") share this sidecar: if they used the old password they no longer open with it"
                    )
            else:
                lines.append(
                    f"  Sidecar password file left unchanged (it does not hold this database's password): {sidecar}"
                )
        if lines:
            self.say("\n".join(lines))
        if failure is not None:
            self.error(str(failure))
        self._warn_stale_environment()
        if failure is None:
            return exit_codes.OK
        return exit_codes.DB_ACCESS if isinstance(failure, RekeyVerifyError) else exit_codes.ERROR

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
        if self.flag(args, "generate"):
            return secrets.token_urlsafe(32), True
        password_file = self.opt(args, "new_password_file", str)
        if password_file is not None:
            if not password_file.strip():
                raise InputError("--new-password-file was given an empty path")
            return read_credential_file("--new-password-file", password_file), False
        if self.flag(args, "new_password_stdin"):
            return read_stdin_line("--new-password-stdin"), False
        if sys.stdin.isatty():
            first = getpass.getpass("New master password: ")
            if not first:
                raise InputError("The new password cannot be empty")
            if getpass.getpass("Repeat new master password: ") != first:
                raise InputError("The passwords do not match")
            return first, False
        return None, False
