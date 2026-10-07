"""Generate or hash API keys for the scoped key policy.

    python -m app.keytool --id billing --ops read --prefix billing-
    echo -n "$EXISTING_KEY" | python -m app.keytool --id deploy --ops read,write --stdin

Prints the key (once -- it is not stored anywhere) and the JSON policy entry containing only its SHA-256.
"""

import argparse
import hashlib
import json
import secrets
import sys

from .security.api_keys import VALID_OPS


def build_entry(key_id: str, key: str, ops: list[str], prefixes: list[str]) -> dict[str, object]:
    entry: dict[str, object] = {
        "id": key_id,
        "key_sha256": hashlib.sha256(key.encode("utf-8")).hexdigest(),
        "ops": ops,
    }
    if prefixes:
        entry["prefixes"] = prefixes
    return entry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.keytool", description=__doc__.split("\n\n")[0])
    parser.add_argument("--id", required=True, help="Key id shown in the audit log (letters, digits, _ . -)")
    parser.add_argument("--ops", default="read", help=f"Comma-separated operations from {sorted(VALID_OPS)}")
    parser.add_argument("--prefix", action="append", default=[], help="Allowed credential-name prefix (repeatable)")
    parser.add_argument("--stdin", action="store_true", help="Hash a key read from stdin instead of generating one")
    args = parser.parse_args(argv)

    ops = [o.strip() for o in args.ops.split(",") if o.strip()]
    unknown = sorted(set(ops) - VALID_OPS)
    if unknown or not ops:
        parser.error(f"invalid --ops; valid values: {sorted(VALID_OPS)}")

    if args.stdin:
        key = sys.stdin.read().rstrip("\r\n")
        if not key:
            parser.error("no key received on stdin")
    else:
        key = secrets.token_urlsafe(32)
        print(f"API key (shown once, give it to the client): {key}", file=sys.stderr)

    print(json.dumps(build_entry(args.id, key, ops, args.prefix), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
