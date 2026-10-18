"""
mattstash.cli.handlers.put
--------------------------
Handler for the put command.

Secrets can be supplied without touching ``argv`` (which is visible through ``ps`` and shell
history): ``--value -`` / ``--value-file`` for simple secrets, ``--entry-password-file`` /
``--entry-password-stdin`` for the password of a full credential.

``-i``/``--interactive`` prompts on the terminal instead: for the username and password (the default), or only
the value with ``--value`` (given without an argument). The title is prompted for when it is omitted.

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
from ...utils.exceptions import InvalidCredentialError
from ...utils.validation import ALLOW_SLASH_NAMES_ENV, slash_names_allowed, validate_credential_title
from .. import exit_codes
from ..inputs import (
    InputError,
    StdinClaim,
    prompt_line,
    prompt_new_secret,
    read_secret_file,
    read_stdin_secret,
    require_terminal,
)
from .base import DB_ERRORS, BaseHandler

_ENTRY_PW_DEPRECATION = (
    "--password for 'put --fields' is deprecated: use --entry-password-file or --entry-password-stdin "
    "(or --entry-password). Anything on the command line is visible to other users (ps, shell history). "
    "Use --db-password-file, KDBX_PASSWORD_FILE or KDBX_PASSWORD for the database password."
)

#: ``--value`` given without an argument (prompt for it). NUL cannot appear in a command-line argument.
VALUE_PROMPT = "\0prompt"


@dataclass
class PutRequest:
    """What ``put`` should store, after mode detection and reading all secret inputs."""

    title: str
    fields: bool
    value: Optional[str] = None
    entry_password: Optional[str] = None
    #: Database password override (None: resolve from KDBX_PASSWORD / KDBX_PASSWORD_FILE / sidecar).
    db_password: Optional[str] = None
    username: Optional[str] = None


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
                    request.title,
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
                        print(f"{request.title}: OK")
                return exit_codes.OK

            # Fields mode: the entry password is stored in the entry; the database password
            # comes from --db-password*/KDBX_PASSWORD*/the sidecar, never from the entry password.
            result = put(
                request.title,
                path=args.path,
                db_password=request.db_password,
                username=request.username,
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
                print(f"{request.title}: OK")
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
        title = self.opt(args, "title", str)
        if self.flag(args, "interactive") or value_arg == VALUE_PROMPT:
            return self._build_interactive_request(args, title, value_arg == VALUE_PROMPT)
        if not title:
            raise InputError("a title is required (or use -i to be prompted for it)")

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
            return PutRequest(title=title, fields=False, value=value, db_password=cli_password)

        # Fields mode. --db-password / --db-password-file are the database password; a plain --password
        # is the deprecated spelling of --entry-password (this command's historical meaning).
        entry_password: Optional[str] = None
        db_password: Optional[str] = cli_password if db_password_flag else None
        if entry_pw == "-":
            raise InputError("--entry-password - would store a literal '-': use --entry-password-stdin to read stdin")
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
        return PutRequest(
            title=title, fields=True, entry_password=entry_password, db_password=db_password, username=username
        )

    def _build_interactive_request(self, args: Namespace, title: Optional[str], value_mode: bool) -> PutRequest:
        """``-i`` (or a bare ``--value``): prompt for the title if omitted, then the secret. Raises ``InputError``."""
        for name, option in (
            ("value_file", "--value-file"),
            ("entry_password", "--entry-password"),
            ("entry_password_file", "--entry-password-file"),
        ):
            if self.opt(args, name, str) is not None:
                raise InputError(f"-i prompts for the secret and cannot be combined with {option}")
        if self.flag(args, "entry_password_stdin"):
            raise InputError("-i prompts for the secret and cannot be combined with --entry-password-stdin")
        value_arg = self.opt(args, "value", str)
        if value_arg is not None and not value_mode:
            raise InputError(
                "-i prompts for the value, so --value takes no argument here; put the title first: "
                "mattstash put TITLE -i --value"
            )
        username = self.opt(args, "username", str)
        if value_mode and (self.flag(args, "fields") or username or self.opt(args, "url", str)):
            raise InputError("--value stores a simple secret: drop --value to be prompted for a username and password")
        db_password_flag = self.flag(args, "db_password_explicit")
        cli_password = self.opt(args, "password", str)
        if cli_password and not db_password_flag and not value_mode:
            raise InputError("-i prompts for the entry password: use --db-password for the database password")

        require_terminal("-i")
        if not title:
            title = prompt_line("Key: ")
            if not title:
                raise InputError("a title is required")
        if value_mode:
            return PutRequest(title=title, fields=False, value=prompt_new_secret("Password"), db_password=cli_password)
        if username is None:
            username = prompt_line("Username: ") or None
        return PutRequest(
            title=title,
            fields=True,
            entry_password=prompt_new_secret("Password"),
            db_password=cli_password if db_password_flag else None,
            username=username,
        )

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
        if "/" in request.title:  # refuse early, with the advice, instead of the server's bare 400
            try:
                validate_credential_title(request.title)
            except InvalidCredentialError as exc:
                note = ""
                if not slash_names_allowed():
                    note = (
                        f". In server mode the SERVER must also have {ALLOW_SLASH_NAMES_ENV}=true, "
                        "otherwise it answers 404 for such names"
                    )
                self.error(f"{exc}{note}")
                return exit_codes.ERROR
        try:
            client = self.get_server_client(args)
            if client is None:
                return exit_codes.ERROR

            # Determine if simple value mode or fields mode
            kwargs = {}
            if not request.fields:
                kwargs["value"] = request.value
            else:
                if request.username:
                    kwargs["username"] = request.username
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

            result = client.put(request.title, **kwargs)

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"{request.title}: OK")

            return exit_codes.OK

        except Exception as e:
            self.error(f"Server error: {e!s}")
            return exit_codes.ERROR
