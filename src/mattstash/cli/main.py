"""
mattstash.cli.main
------------------
Command-line interface for MattStash.
"""

import argparse
import os
import sys
from importlib.metadata import version as _pkg_version
from typing import Any, Optional

from ..utils.exceptions import MattStashError
from . import exit_codes
from .handlers import (
    ConfigHandler,
    DbUrlHandler,
    DeleteHandler,
    GetHandler,
    KeysHandler,
    ListHandler,
    PruneHandler,
    PutHandler,
    S3TestHandler,
    SetupHandler,
    VersionsHandler,
)
from .handlers.base import DB_ERRORS
from .inputs import InputError, read_credential_file


class _DbPasswordAction(argparse.Action):
    """Store the DB password; remember whether the unambiguous ``--db-password`` spelling was used.

    ``put --fields`` historically read a bare ``--password`` as the *entry* password; ``--db-password``
    always means the database password.
    """

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: Optional[str] = None,
    ) -> None:
        setattr(namespace, self.dest, values)
        if option_string != "--password":
            namespace.db_password_explicit = True


def _resolve_db_password_file(args: argparse.Namespace) -> None:
    """Turn ``--db-password-file`` into ``args.password`` (an explicit DB password). Raises ``InputError``."""
    path = getattr(args, "db_password_file", None)
    if not path:
        return
    if getattr(args, "password", None):
        raise InputError("--password/--db-password and --db-password-file are mutually exclusive")
    args.password = read_credential_file("--db-password-file", path)
    args.db_password_explicit = True
    args.db_password_from_file = True


def _non_negative_int(text: str) -> int:
    try:
        number = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid integer: {text!r}") from None
    if number < 0:
        raise argparse.ArgumentTypeError("must be 0 or greater")
    return number


def _add_global_options(parser: argparse.ArgumentParser, *, suppress_defaults: bool) -> None:
    """Options shared by every command (accepted before or after the subcommand)."""
    unset: Any = argparse.SUPPRESS if suppress_defaults else None

    parser.add_argument(
        "--db",
        dest="path",
        default=unset,
        help="Path to KeePass .kdbx (default: ~/.config/mattstash/mattstash.kdbx)",
    )
    parser.add_argument(
        "--password",
        "--db-password",
        dest="password",
        action=_DbPasswordAction,
        default=unset,
        metavar="PASSWORD",
        help="Password for the KeePass DB (overrides KDBX_PASSWORD/KDBX_PASSWORD_FILE/sidecar). Visible to other "
        "users via ps and shell history: prefer --db-password-file, KDBX_PASSWORD_FILE or KDBX_PASSWORD. "
        "--db-password is the unambiguous spelling (for 'put --fields', a bare --password still means the entry "
        "password, deprecated)",
    )
    parser.add_argument(
        "--db-password-file",
        dest="db_password_file",
        default=unset,
        metavar="FILE",
        help="Read the KeePass DB password from this file (surrounding whitespace is stripped)",
    )
    parser.add_argument(
        "--server-url",
        dest="server_url",
        default=unset if suppress_defaults else os.environ.get("MATTSTASH_SERVER_URL"),
        help="MattStash server URL (enables server mode). Can also use MATTSTASH_SERVER_URL env var.",
    )
    parser.add_argument(
        "--api-key",
        dest="api_key",
        default=unset,
        help="API key for server authentication (visible to other users via ps and shell history: prefer "
        "--api-key-file or the MATTSTASH_API_KEY / MATTSTASH_API_KEY_FILE environment variables)",
    )
    parser.add_argument(
        "--api-key-file",
        dest="api_key_file",
        default=unset,
        metavar="FILE",
        help="Read the server API key from this file. Can also use MATTSTASH_API_KEY_FILE env var.",
    )
    parser.add_argument(
        "--verbose", action="store_true", default=unset if suppress_defaults else False, help="Verbose output"
    )


def main(argv: Optional[list[str]] = None) -> int:
    """
    Simple CLI:
      - setup: create a new database (the only command that creates one)
      - list: show all entries
      - get:  fetch a single entry by title
      - put:  create or update an entry (simple or full)
      - s3-test: construct a client and optionally head a bucket
    """
    argv = list(sys.argv[1:] if argv is None else argv)

    # Two parent parsers so global options work before OR after the subcommand
    # (e.g. both `mattstash --db X get foo` and `mattstash get foo --db X`).
    # The subparser parent uses SUPPRESS defaults to avoid clobbering values
    # already parsed by the main parser.
    global_opts = argparse.ArgumentParser(add_help=False)
    _add_global_options(global_opts, suppress_defaults=True)

    parser = argparse.ArgumentParser(
        prog="mattstash",
        description="KeePass-backed secrets accessor",
    )
    _add_global_options(parser, suppress_defaults=False)
    parser.add_argument("--version", action="version", version=f"%(prog)s {_pkg_version('mattstash')}")

    subparsers = parser.add_subparsers(dest="cmd", required=True)

    # setup
    p_setup = subparsers.add_parser("setup", help="Create a new database", parents=[global_opts])
    p_setup.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing database (existing files are backed up first; asks for confirmation)",
    )
    p_setup.add_argument("--yes", action="store_true", help="Do not ask for confirmation when using --force")
    p_setup.add_argument("--no-backup", action="store_true", help="With --force, do not back up replaced files")
    p_pw = p_setup.add_argument_group("master password (default: prompt; or KDBX_PASSWORD / KDBX_PASSWORD_FILE)")
    p_pw.add_argument(
        "--sidecar",
        action="store_true",
        help="Generate a random password and store it in <db dir>/.mattstash.txt (0600). "
        "Convenient, but the key then sits next to the database.",
    )
    p_pw.add_argument("--generate", action="store_true", help="Generate a random password and print it once")
    p_pw.add_argument("--password-file", help="Read the master password from this file")
    p_pw.add_argument("--password-stdin", action="store_true", help="Read the master password from stdin")

    # list
    p_list = subparsers.add_parser("list", help="List entries", parents=[global_opts])
    p_list.add_argument("--show-password", action="store_true", help="Show passwords in output")
    p_list.add_argument("--json", action="store_true", help="Output JSON")

    # keys
    p_keys = subparsers.add_parser("keys", help="List entry titles only", parents=[global_opts])
    p_keys.add_argument(
        "--show-password", action="store_true", help="Show passwords in output"
    )  # For symmetry, but not used
    p_keys.add_argument("--json", action="store_true", help="Output JSON")

    # get
    p_get = subparsers.add_parser("get", help="Get a single entry by title", parents=[global_opts])
    p_get.add_argument("title", help="KeePass entry title")
    p_get.add_argument("--show-password", action="store_true", help="Show password in output")
    p_get.add_argument("--version", type=int, help="Specific version to retrieve")
    p_get_format = p_get.add_mutually_exclusive_group()
    p_get_format.add_argument("--json", action="store_true", help="Output JSON")
    p_get_format.add_argument(
        "--raw",
        action="store_true",
        help="Print only the secret (password/value) followed by a newline, unmasked, and nothing else; "
        "for scripts, e.g. TOKEN=$(mattstash get my-token --raw). Exit status 2 if not found",
    )
    p_get.add_argument(
        "--field",
        choices=["password", "username", "url", "notes"],
        help="With --raw: the field to print (default: password). Simple secrets only have a password/value",
    )

    # put
    p_put = subparsers.add_parser("put", help="Create/update an entry", parents=[global_opts])
    p_put.add_argument("title", help="KeePass entry title")
    group = p_put.add_mutually_exclusive_group(required=False)
    group.add_argument(
        "--value",
        metavar="VALUE",
        help="Simple secret value (credstash-like; stored in the password field). Use '-' to read it from stdin; "
        "a value on the command line is visible via ps and shell history",
    )
    group.add_argument(
        "--value-file",
        metavar="FILE",
        help="Read the simple secret value from FILE (one trailing newline is removed)",
    )
    group.add_argument(
        "--fields",
        action="store_true",
        help="Store a full credential from --username/--url/--entry-password*/--notes instead of a simple value "
        "(inferred when any of --username, --url or --entry-password* is given)",
    )
    p_put.add_argument("--username", help="Username (full credential)")
    p_put.add_argument("--url", help="URL or host:port (full credential)")
    p_entry_pw = p_put.add_argument_group(
        "entry password (full credentials; selects --fields; at most one; the DB password is --db-password*)"
    )
    p_entry_pw.add_argument(
        "--entry-password",
        metavar="PASSWORD",
        help="Password to store in the entry. Visible via ps and shell history: prefer the file/stdin options",
    )
    p_entry_pw.add_argument(
        "--entry-password-file",
        metavar="FILE",
        help="Read the entry password from FILE (one trailing newline is removed)",
    )
    p_entry_pw.add_argument(
        "--entry-password-stdin",
        action="store_true",
        help="Read the entry password from stdin (one trailing newline is removed)",
    )
    p_put.add_argument("--notes", help="Notes or comments for this entry")
    p_put.add_argument("--comment", help="Alias for --notes (notes/comments for this entry)")
    p_put.add_argument("--tag", action="append", dest="tags", help="Repeatable; adds a tag")
    p_put.add_argument("--json", action="store_true", help="Output JSON")

    # delete
    p_del = subparsers.add_parser(
        "delete", help="Delete an entry (all versions, or one with --version)", parents=[global_opts]
    )
    p_del.add_argument("title", help="KeePass entry title to delete")
    p_del.add_argument(
        "--version",
        type=_non_negative_int,
        metavar="N",
        help="Delete only version N and keep the others (without this option ALL versions are deleted)",
    )

    # prune
    p_prune = subparsers.add_parser(
        "prune",
        help="Delete all but the newest N versions of a secret (local database only)",
        parents=[global_opts],
    )
    p_prune.add_argument("title", help="Base title of the secret")
    p_prune.add_argument(
        "--keep",
        type=int,
        required=True,
        metavar="N",
        help="Number of newest versions to keep (at least 1)",
    )

    # versions
    p_versions = subparsers.add_parser("versions", help="List versions for a key", parents=[global_opts])
    p_versions.add_argument("title", help="Base key title")
    p_versions.add_argument("--json", action="store_true", help="Output JSON")

    # db-url
    p_dburl = subparsers.add_parser(
        "db-url",
        help="Print SQLAlchemy-style URL from a DB credential",
        parents=[global_opts],
    )
    p_dburl.add_argument("title", help="KeePass entry title holding DB connection fields")
    p_dburl.add_argument("--driver", default="psycopg", help="Driver name suffix in URL (default: psycopg)")
    p_dburl.add_argument(
        "--database", help="Database name; if omitted, use credential custom property 'database'/'dbname'"
    )
    p_dburl.add_argument(
        "--mask-password",
        default=True,
        nargs="?",
        const=True,
        type=lambda s: str(s).lower() not in ("false", "0", "no", "off"),
        help="Mask password in printed URL (default True). Pass 'False' to disable.",
    )

    # s3-test
    p_s3 = subparsers.add_parser(
        "s3-test",
        help="Create an S3 client from a credential and optionally check a bucket",
        parents=[global_opts],
    )
    p_s3.add_argument("title", help="KeePass entry title holding S3 endpoint/key/secret")
    p_s3.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    p_s3.add_argument("--addressing", choices=["path", "virtual"], default="path", help="S3 addressing style")
    p_s3.add_argument("--signature-version", default="s3v4", help="Signature version (default: s3v4)")
    p_s3.add_argument("--retries-max-attempts", type=int, default=10, help="Max retries (default: 10)")
    p_s3.add_argument("--bucket", help="If provided, issue a HeadBucket to test connectivity")
    p_s3.add_argument("--quiet", action="store_true", help="Only exit code, no prints")

    # config
    p_config = subparsers.add_parser("config", help="Generate example configuration file", parents=[global_opts])
    p_config.add_argument("--output", help="Output path for config file (default: ~/.config/mattstash/config.yml)")

    # server (informational only — the server is a separate Docker image)
    subparsers.add_parser(
        "server",
        help="Show how to run the MattStash API server",
        parents=[global_opts],
    )

    args = parser.parse_args(argv)

    # Handle the informational 'server' subcommand
    if args.cmd == "server":
        print(
            "The MattStash API server runs as a separate Docker container, not as a CLI subcommand.\n"
            "\n"
            "Quick start:\n"
            "  docker run -d \\\n"
            "    -e MATTSTASH_DB_PATH=/data/mattstash.kdbx \\\n"
            "    -e KDBX_PASSWORD=<password> \\\n"
            "    -e MATTSTASH_API_KEY=<api-key> \\\n"
            "    -v /path/to/data:/data:ro \\\n"
            "    -p 8000:8000 \\\n"
            "    ghcr.io/cornyhorse/mattstash:latest\n"
            "\n"
            "Then point the CLI at the server:\n"
            "  export MATTSTASH_SERVER_URL=http://localhost:8000\n"
            "  export MATTSTASH_API_KEY=<api-key>\n"
            "  mattstash get my-secret\n"
            "\n"
            "Full documentation: https://github.com/cornyhorse/mattstash/tree/main/server"
        )
        return 0

    # Command handler mapping
    handlers = {
        "setup": SetupHandler(),
        "list": ListHandler(),
        "keys": KeysHandler(),
        "get": GetHandler(),
        "put": PutHandler(),
        "delete": DeleteHandler(),
        "prune": PruneHandler(),
        "versions": VersionsHandler(),
        "db-url": DbUrlHandler(),
        "s3-test": S3TestHandler(),
        "config": ConfigHandler(),
    }

    # Get the appropriate handler and execute it
    handler = handlers.get(args.cmd)
    if handler:
        try:
            _resolve_db_password_file(args)
            return handler.handle(args)
        except InputError as e:
            print(f"mattstash: {e}", file=sys.stderr)
            return exit_codes.ERROR
        except DB_ERRORS as e:
            return handler.db_error(e)
        except MattStashError as e:
            print(f"mattstash: {e}", file=sys.stderr)
            return exit_codes.ERROR

    # Should not reach here
    return 1  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
