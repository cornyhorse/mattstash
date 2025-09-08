"""
mattstash.cli
-------------
Command-line interface for MattStash.
"""

import sys
import argparse
import json
from typing import Optional

from .core import MattStash
from .credential import Credential, serialize_credential
from .module_functions import get, put, delete, list_creds, list_versions, get_db_url, get_s3_client


def main(argv: Optional[list[str]] = None) -> int:
    """
    Simple CLI:
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

    # Prepare instance (module-level helpers handle caching)
    if args.cmd == "put":
        if args.value is not None and not args.fields:
            result = put(
                args.title,
                path=args.path,
                db_password=args.password,
                value=args.value,
                notes=args.notes,
                comment=args.comment,
                tags=args.tags,
            )
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                if isinstance(result, dict):
                    print(f"{result['name']}: {result['value']}")
                else:
                    print(f"{args.title}: OK")
            return 0
        # fields mode
        result = put(
            args.title,
            path=args.path,
            db_password=args.password,
            username=args.username,
            password=args.password,
            url=args.url,
            notes=args.notes,
            comment=args.comment,
            tags=args.tags,
        )
        if args.json:
            if isinstance(result, dict):
                print(json.dumps(result, indent=2))
            else:
                print(json.dumps(serialize_credential(result, show_password=False), indent=2))
        else:
            print(f"{args.title}: OK")
        return 0

    if args.cmd == "list":
        creds = list_creds(path=args.path, password=args.password, show_password=args.show_password)
        if args.json:
            payload = [serialize_credential(c, show_password=args.show_password) for c in creds]
            print(json.dumps(payload, indent=2))
        else:
            for c in creds:
                pwd_disp = c.password if args.show_password else ("*****" if c.password else None)
                notes_snippet = ""
                if c.notes and c.notes.strip():
                    snippet = c.notes.strip().splitlines()[0]
                    notes_snippet = f" notes={snippet!r}"
                print(
                    f"- {c.credential_name} user={c.username!r} url={c.url!r} pwd={pwd_disp!r} tags={c.tags}{notes_snippet}")
        return 0

    if args.cmd == "keys":
        creds = list_creds(path=args.path, password=args.password, show_password=args.show_password)
        titles = [c.credential_name for c in creds]
        if args.json:
            print(json.dumps(titles, indent=2))
        else:
            for t in titles:
                print(t)
        return 0

    if args.cmd == "get":
        c = get(args.title, path=args.path, password=args.password, show_password=args.show_password)
        if not c:
            print(f"[mattstash] not found: {args.title}", file=sys.stderr)
            return 2
        if args.json:
            if isinstance(c, dict):
                # simple-secret mode already respects --show-password via get(show_password=...)
                print(json.dumps(c, indent=2))
            else:
                print(json.dumps(serialize_credential(c, show_password=args.show_password), indent=2))
        else:
            if isinstance(c, dict):
                print(f"{c['name']}")
                print(f"  value: {c['value']}")
            else:
                pwd_disp = c.password if args.show_password else ("*****" if c.password else None)
                print(f"{c.credential_name}")
                print(f"  username: {c.username}")
                print(f"  password: {pwd_disp}")
                print(f"  url:      {c.url}")
                print(f"  tags:     {', '.join(c.tags) if c.tags else ''}")
                if c.notes:
                    print("  notes/comments:")
                    for line in (c.notes or '').splitlines():
                        print(f"    {line}")
        return 0

    if args.cmd == "delete":
        ok = delete(args.title, path=args.path, password=args.password)
        if ok:
            print(f"{args.title}: deleted")
            return 0
        else:
            return 2

    if args.cmd == "versions":
        vers = list_versions(args.title, path=args.path, password=args.password)
        if args.json:
            print(json.dumps(vers, indent=2))
        else:
            for v in vers:
                print(v)
        return 0

    if args.cmd == "db-url":
        try:
            url = get_db_url(
                args.title,
                path=args.path,
                password=args.password,
                driver=args.driver,
                mask_password=args.mask_password,
                mask_style="omit",  # CLI masks by omission (no placeholder)
                database=args.database,
            )
            print(url)
            return 0
        except Exception as e:
            print(f"[mattstash] failed to build DB URL: {e}", file=sys.stderr)
            return 5

    if args.cmd == "s3-test":
        try:
            client = get_s3_client(
                args.title,
                path=args.path,
                password=args.password,
                region=args.region,
                addressing=args.addressing,
                signature_version=args.signature_version,
                retries_max_attempts=args.retries_max_attempts,
                verbose=not args.quiet,
            )
        except Exception as e:
            if not args.quiet:
                print(f"[mattstash] failed to create S3 client: {e}", file=sys.stderr)
            return 3

        if args.bucket:
            try:
                client.head_bucket(Bucket=args.bucket)
                if not args.quiet:
                    print(f"[mattstash] HeadBucket OK for {args.bucket}")
                return 0
            except Exception as e:
                if not args.quiet:
                    print(f"[mattstash] HeadBucket FAILED for {args.bucket}: {e}", file=sys.stderr)
                return 4
        else:
            if not args.quiet:
                print("[mattstash] S3 client created successfully")
            return 0

    # Should not reach here
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
