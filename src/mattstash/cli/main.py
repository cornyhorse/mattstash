"""
mattstash.cli.main
------------------
Command-line interface for MattStash.
"""

import sys
import argparse
from typing import Optional

from .handlers import (
    SetupHandler,
    ListHandler,
    KeysHandler,
    GetHandler,
    PutHandler,
    DeleteHandler,
    VersionsHandler,
    DbUrlHandler,
    S3TestHandler,
)


def main(argv: Optional[list[str]] = None) -> int:
    """
    Simple CLI:
      - setup: create database and sidecar password file
      - list: show all entries
      - get:  fetch a single entry by title
      - put:  create or update an entry (simple or full)
      - s3-test: construct a client and optionally head a bucket
    """
    argv = list(sys.argv[1:] if argv is None else argv)

    parser = argparse.ArgumentParser(prog="mattstash", description="KeePass-backed secrets accessor")
    parser.add_argument("--db", dest="path", help="Path to KeePass .kdbx (default: ~/.config/mattstash/mattstash.kdbx)")
    parser.add_argument("--password", dest="password", help="Password for the KeePass DB (overrides sidecar/env)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    subparsers = parser.add_subparsers(dest="cmd", required=True)

    # setup
    p_setup = subparsers.add_parser("setup", help="Create database and sidecar password file")
    p_setup.add_argument("--force", action="store_true", help="Force creation even if files already exist")

    # list
    p_list = subparsers.add_parser("list", help="List entries")
    p_list.add_argument("--show-password", action="store_true", help="Show passwords in output")
    p_list.add_argument("--json", action="store_true", help="Output JSON")

    # keys
    p_keys = subparsers.add_parser("keys", help="List entry titles only")
    p_keys.add_argument("--show-password", action="store_true",
                        help="Show passwords in output")  # For symmetry, but not used
    p_keys.add_argument("--json", action="store_true", help="Output JSON")

    # get
    p_get = subparsers.add_parser("get", help="Get a single entry by title")
    p_get.add_argument("title", help="KeePass entry title")
    p_get.add_argument("--show-password", action="store_true", help="Show password in output")
    p_get.add_argument("--json", action="store_true", help="Output JSON")

    # put
    p_put = subparsers.add_parser("put", help="Create/update an entry")
    p_put.add_argument("title", help="KeePass entry title")
    group = p_put.add_mutually_exclusive_group(required=True)
    group.add_argument("--value", help="Simple secret value (credstash-like; stored in password field)")
    group.add_argument("--fields", action="store_true", help="Provide explicit fields instead of --value")
    p_put.add_argument("--username")
    p_put.add_argument("--password")
    p_put.add_argument("--url")
    p_put.add_argument("--notes", help="Notes or comments for this entry")
    p_put.add_argument("--comment", help="Alias for --notes (notes/comments for this entry)")
    p_put.add_argument("--tag", action="append", dest="tags", help="Repeatable; adds a tag")
    p_put.add_argument("--json", action="store_true", help="Output JSON")

    # delete
    p_del = subparsers.add_parser("delete", help="Delete an entry by title")
    p_del.add_argument("title", help="KeePass entry title to delete")

    # versions
    p_versions = subparsers.add_parser("versions", help="List versions for a key")
    p_versions.add_argument("title", help="Base key title")
    p_versions.add_argument("--json", action="store_true", help="Output JSON")

    # db-url
    p_dburl = subparsers.add_parser("db-url", help="Print SQLAlchemy-style URL from a DB credential")
    p_dburl.add_argument("title", help="KeePass entry title holding DB connection fields")
    p_dburl.add_argument("--driver", default="psycopg", help="Driver name suffix in URL (default: psycopg)")
    p_dburl.add_argument("--database", help="Database name; if omitted, use credential custom property 'database'/'dbname'")
    p_dburl.add_argument("--mask-password", default=True, nargs="?", const=True,
                         type=lambda s: (str(s).lower() not in ("false", "0", "no", "off")),
                         help="Mask password in printed URL (default True). Pass 'False' to disable.")

    # s3-test
    p_s3 = subparsers.add_parser("s3-test", help="Create an S3 client from a credential and optionally check a bucket")
    p_s3.add_argument("title", help="KeePass entry title holding S3 endpoint/key/secret")
    p_s3.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    p_s3.add_argument("--addressing", choices=["path", "virtual"], default="path", help="S3 addressing style")
    p_s3.add_argument("--signature-version", default="s3v4", help="Signature version (default: s3v4)")
    p_s3.add_argument("--retries-max-attempts", type=int, default=10, help="Max retries (default: 10)")
    p_s3.add_argument("--bucket", help="If provided, issue a HeadBucket to test connectivity")
    p_s3.add_argument("--quiet", action="store_true", help="Only exit code, no prints")

    args = parser.parse_args(argv)

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
    }

    # Get the appropriate handler and execute it
    handler = handlers.get(args.cmd)
    if handler:
        return handler.handle(args)

    # Should not reach here
    return 1  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
