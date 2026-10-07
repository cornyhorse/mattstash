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
    PutHandler,
    S3TestHandler,
    SetupHandler,
    VersionsHandler,
)
from .handlers.base import DB_ERRORS


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
        dest="password",
        default=unset,
        help="Password for the KeePass DB (overrides KDBX_PASSWORD/KDBX_PASSWORD_FILE/sidecar). "
        "Visible to other users via ps and shell history: prefer KDBX_PASSWORD_FILE or KDBX_PASSWORD",
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
    p_get.add_argument("--json", action="store_true", help="Output JSON")
    p_get.add_argument("--version", type=int, help="Specific version to retrieve")

    # put
    p_put = subparsers.add_parser("put", help="Create/update an entry", parents=[global_opts])
    p_put.add_argument("title", help="KeePass entry title")
    group = p_put.add_mutually_exclusive_group(required=False)
    group.add_argument("--value", help="Simple secret value (credstash-like; stored in password field)")
    group.add_argument("--fields", action="store_true", help="Provide explicit fields instead of --value")
    p_put.add_argument("--username")
    p_put.add_argument("--url")
    p_put.add_argument("--notes", help="Notes or comments for this entry")
    p_put.add_argument("--comment", help="Alias for --notes (notes/comments for this entry)")
    p_put.add_argument("--tag", action="append", dest="tags", help="Repeatable; adds a tag")
    p_put.add_argument("--json", action="store_true", help="Output JSON")

    # delete
    p_del = subparsers.add_parser("delete", help="Delete an entry by title", parents=[global_opts])
    p_del.add_argument("title", help="KeePass entry title to delete")

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
        "versions": VersionsHandler(),
        "db-url": DbUrlHandler(),
        "s3-test": S3TestHandler(),
        "config": ConfigHandler(),
    }

    # Get the appropriate handler and execute it
    handler = handlers.get(args.cmd)
    if handler:
        try:
            return handler.handle(args)
        except DB_ERRORS as e:
            return handler.db_error(e)
        except MattStashError as e:
            print(f"mattstash: {e}", file=sys.stderr)
            return exit_codes.ERROR

    # Should not reach here
    return 1  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
