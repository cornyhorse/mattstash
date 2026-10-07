"""
mattstash.cli.handlers.put
--------------------------
Handler for the put command.

Secrets can be supplied without touching ``argv`` (which is visible through ``ps`` and shell
history): ``--value -`` / ``--value-file`` for simple secrets, ``--entry-password-file`` /
``--entry-password-stdin`` for the password of a full credential.

``--password`` is the *database* password everywhere except ``put --fields``, where it used to
mean the entry password. That meaning still works but is deprecated; ``--db-password`` always
means the database password and ``--entry-password*`` always means the entry password.
"""

import json
from argparse import Namespace
from dataclasses import dataclass
from typing import Optional

from ...models.credential import serialize_credential
from ...module_functions import put
from .. import exit_codes
from ..inputs import InputError, StdinClaim, read_secret_file, read_stdin_secret
from .base import DB_ERRORS, BaseHandler

_ENTRY_PW_DEPRECATION = (
    "--password for 'put --fields' is deprecated: use --entry-password-file or --entry-password-stdin "
    "(or --entry-password). Anything on the command line is visible to other users (ps, shell history). "
    "Use --db-password-file, KDBX_PASSWORD_FILE or KDBX_PASSWORD for the database password."
)


@dataclass
class PutRequest:
    """What ``put`` should store, after mode detection and reading all secret inputs."""

    fields: bool
    value: Optional[str] = None
    entry_password: Optional[str] = None
    #: Database password override (None: resolve from KDBX_PASSWORD / KDBX_PASSWORD_FILE / sidecar).
    db_password: Optional[str] = None


class PutHandler(BaseHandler):
    """Handler for the put command."""

    def handle(self, args: Namespace) -> int:
        """Handle the put command."""
        try:
            request = self._build_request(args)
        except InputError as exc:
            self.error(str(exc))
            return exit_codes.ERROR

        # Check if server mode
        if self.is_server_mode(args):
            return self._handle_server_mode(args, request)

        # Local mode
        try:
            if not request.fields:
                # Simple value mode (credstash-like)
                result = put(
                    args.title,
                    path=args.path,
                    db_password=request.db_password,
                    value=request.value,
                    notes=args.notes,
                    comment=args.comment,
                    tags=args.tags,
                )
                if result is None:
                    self.error("Failed to store credential (database may be inaccessible)")
                    return exit_codes.ERROR
                if args.json:
                    print(json.dumps(result, indent=2))
                else:
                    if isinstance(result, dict):
                        print(f"{result['name']}: {result['value']}")
                    else:
                        print(f"{args.title}: OK")
                return exit_codes.OK

            # Fields mode: the entry password is stored in the entry; the database password
            # comes from --db-password*/KDBX_PASSWORD*/the sidecar, never from the entry password.
            result = put(
                args.title,
                path=args.path,
                db_password=request.db_password,
                username=args.username,
                password=request.entry_password,
                url=args.url,
                notes=args.notes,
                comment=args.comment,
                tags=args.tags,
            )
            if result is None:
                self.error("Failed to store credential (database may be inaccessible)")
                return exit_codes.ERROR
            if args.json:
                if isinstance(result, dict):
                    print(json.dumps(result, indent=2))
                else:
                    print(json.dumps(serialize_credential(result, show_password=False), indent=2))
            else:
                print(f"{args.title}: OK")
            return exit_codes.OK
        except DB_ERRORS as e:
            return self.db_error(e)
        except Exception as e:
            self.error(str(e))
            return exit_codes.ERROR

    # ---- argument interpretation ---------------------------------------------

    def _build_request(self, args: Namespace) -> PutRequest:
        """Decide the mode and read every secret input exactly once. Raises ``InputError``."""
        value_arg = self.opt(args, "value", str)
        value_file = self.opt(args, "value_file", str)
        entry_pw = self.opt(args, "entry_password", str)
        entry_pw_file = self.opt(args, "entry_password_file", str)
        entry_pw_stdin = self.flag(args, "entry_password_stdin")
        username = self.opt(args, "username", str)
        url = self.opt(args, "url", str)
        fields = self.flag(args, "fields")

        has_value = value_arg is not None or value_file is not None
        entry_pw_options = [
            name
            for name, given in (
                ("--entry-password", entry_pw is not None),
                ("--entry-password-file", entry_pw_file is not None),
                ("--entry-password-stdin", entry_pw_stdin),
            )
            if given
        ]

        # Only one option may read stdin: report that before anything else, and before reading it.
        stdin = StdinClaim()
        if value_arg == "-":
            stdin.claim("--value -")
        if entry_pw_stdin:
            stdin.claim("--entry-password-stdin")

        if has_value and fields:
            raise InputError("--value/--value-file and --fields are mutually exclusive")
        if has_value and entry_pw_options:
            raise InputError(
                f"{entry_pw_options[0]} stores a full credential and cannot be combined with --value/--value-file "
                "(use --fields, or drop --value)"
            )
        if has_value and (username or url):
            raise InputError("--username/--url need a full credential: use --fields instead of --value")
        if len(entry_pw_options) > 1:
            raise InputError(" and ".join(entry_pw_options[:2]) + " are mutually exclusive")

        # Auto-select fields mode when any field-specific option is given.
        if not has_value and not fields and (username or url or entry_pw_options):
            fields = True
        if not has_value and not fields:
            raise InputError(
                "one of --value, --value-file or --fields is required "
                "(--fields is inferred when --username, --url or --entry-password* is given)"
            )

        db_password_flag = self.flag(args, "db_password_explicit")
        cli_password = self.opt(args, "password", str)

        if not fields:
            value = self._read_value(value_arg, value_file)
            return PutRequest(fields=False, value=value, db_password=cli_password)

        # Fields mode. --db-password / --db-password-file are the database password; a plain --password
        # is the deprecated spelling of --entry-password (this command's historical meaning).
        entry_password: Optional[str] = None
        db_password: Optional[str] = cli_password if db_password_flag else None
        if entry_pw is not None:
            entry_password = self._non_empty("--entry-password", entry_pw)
        elif entry_pw_file is not None:
            entry_password = read_secret_file("--entry-password-file", entry_pw_file)
        elif entry_pw_stdin:
            entry_password = read_stdin_secret("--entry-password-stdin")
        if cli_password and not db_password_flag:
            if entry_password is not None:
                raise InputError(
                    "--password is ambiguous together with --entry-password*: use --entry-password* for the entry "
                    "password and --db-password / --db-password-file for the database password"
                )
            self.deprecation(_ENTRY_PW_DEPRECATION)
            entry_password = cli_password
        return PutRequest(fields=True, entry_password=entry_password, db_password=db_password)

    @staticmethod
    def _non_empty(option: str, value: str) -> str:
        if value == "":
            raise InputError(f"{option} must not be empty")
        return value

    def _read_value(self, value_arg: Optional[str], value_file: Optional[str]) -> str:
        if value_file is not None:
            return read_secret_file("--value-file", value_file)
        assert value_arg is not None
        if value_arg == "-":
            return read_stdin_secret("--value -")
        return self._non_empty("--value", value_arg)

    # ---- server mode ------------------------------------------------------------

    def _handle_server_mode(self, args: Namespace, request: PutRequest) -> int:
        """Handle put command in server mode."""
        try:
            client = self.get_server_client(args)
            if client is None:
                return exit_codes.ERROR

            # Determine if simple value mode or fields mode
            kwargs = {}
            if not request.fields:
                kwargs["value"] = request.value
            else:
                if args.username:
                    kwargs["username"] = args.username
                if request.entry_password is not None:
                    kwargs["password"] = request.entry_password
                if args.url:
                    kwargs["url"] = args.url

            if args.notes:
                kwargs["notes"] = args.notes
            if args.comment:
                kwargs["comment"] = args.comment
            if args.tags:
                kwargs["tags"] = args.tags

            result = client.put(args.title, **kwargs)

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"{args.title}: OK")

            return exit_codes.OK

        except Exception as e:
            self.error(f"Server error: {e!s}")
            return exit_codes.ERROR
