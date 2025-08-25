"""
mattstash.core
--------------
KeePass-backed secrets accessor + optional boto3 S3 client helper.
"""

from __future__ import annotations

import os
import sys
import argparse
import json
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from pykeepass import PyKeePass

try:
    # module-level helper for creating new databases
    from pykeepass import create_database as _kp_create_database  # type: ignore
except Exception:  # pragma: no cover
    _kp_create_database = None


def _ensure_scheme(u: Optional[str]) -> Optional[str]:
    if not u:
        return u
    return u if u.startswith("http://") or u.startswith("https://") else f"https://{u}"


__all__ = [
    "Credential",
    "MattStash",
    "get",
    "list_creds",  # renamed to avoid masking builtin
    "get_s3_client",
]

DEFAULT_KDBX_PATH = os.path.expanduser("~/.config/mattstash/mattstash.kdbx")

# Sidecar plaintext file name stored next to the KDBX DB
DEFAULT_KDBX_SIDECAR_BASENAME = ".mattstash.txt"


@dataclass
class Credential:
    """
    Container for a KeePass entry's commonly used fields.
    """
    credential_name: str
    username: Optional[str]
    password: Optional[str]
    url: Optional[str]
    notes: Optional[str]
    tags: list[str]
    show_password: bool = field(default=False, repr=False)

    def __repr__(self) -> str:
        # Custom repr to mask password if show_password is False
        pwd = self.password if self.show_password else ("*****" if self.password else None)
        return (f"Credential(credential_name={self.credential_name!r}, username={self.username!r}, "
                f"password={pwd!r}, url={self.url!r}, notes={self.notes!r}, tags={self.tags!r})")

    def as_dict(self) -> dict:
        # Provide a dict representation with password masked if show_password is False
        return {
            "credential_name": self.credential_name,
            "username": self.username,
            "password": self.password if self.show_password else ("*****" if self.password else None),
            "url": self.url,
            "notes": self.notes,
            "tags": self.tags,
        }


class MattStash:
    """
    Simple KeePass accessor with:
      - default path of ~/.credentials/mattstash.kdbx (override via ctor)
      - password sources: explicit arg, then sidecar file next to the DB named '.mattstash.txt', then KDBX_PASSWORD environment variable
      - generic get(title) -> Credential
      - optional env hydration (mapping of keepass 'title:FIELD' -> ENVVAR)
    """

    def __init__(self, path: Optional[str] = None, password: Optional[str] = None):
        self.path = os.path.expanduser(path or DEFAULT_KDBX_PATH)
        # Create DB + sidecar if both are missing (credstash-like bootstrap)
        self._bootstrap_if_missing()
        self.password = password or self._resolve_password()
        self._kp: Optional[PyKeePass] = None

    def _bootstrap_if_missing(self) -> None:
        """
        If BOTH the KeePass DB and the sidecar password file are missing, create them.
        This mirrors a credstash-like 'setup' step: we generate a strong password,
        write it to the sidecar, and initialize an empty KeePass database at self.path.
        """
        try:
            db_dir = os.path.dirname(self.path) or "."
            sidecar = os.path.join(db_dir, DEFAULT_KDBX_SIDECAR_BASENAME)
            db_exists = os.path.exists(self.path)
            sidecar_exists = os.path.exists(sidecar)

            if db_exists or sidecar_exists:
                return  # Only bootstrap when BOTH are absent

            # Ensure directory exists with restrictive perms
            os.makedirs(db_dir, exist_ok=True)
            try:
                os.chmod(db_dir, 0o700)
            except Exception:
                # Best-effort on non-POSIX or restricted environments
                pass

            # Generate a strong password for the DB and write the sidecar (0600)
            import secrets
            pw = secrets.token_urlsafe(32)

            with open(sidecar, "wb") as f:
                f.write(pw.encode())
            try:
                os.chmod(sidecar, 0o600)
            except Exception:
                pass

            # Create an empty KeePass database
            try:
                if _kp_create_database is None:
                    raise RuntimeError("pykeepass.create_database not available in this version")
                _kp_create_database(self.path, password=pw)
                print(f"[MattStash] Created new KeePass DB at {self.path} and sidecar {sidecar}", file=sys.stderr)
            except Exception as e:
                print(f"[MattStash] Failed to create KeePass DB at {self.path}: {e}", file=sys.stderr)
        except Exception as e:
            # Non-fatal: we fall back to the normal resolve/open path
            print(f"[MattStash] Bootstrap skipped due to error: {e}", file=sys.stderr)

    def _resolve_password(self) -> Optional[str]:
        # 1) Sidecar plaintext file next to the DB (e.g., ~/.credentials/.mattstash.txt)
        sidecar = os.path.join(os.path.dirname(self.path), DEFAULT_KDBX_SIDECAR_BASENAME)
        try:
            if os.path.exists(sidecar):
                try:
                    with open(sidecar, "rb") as f:
                        pw = f.read().decode().strip()
                        print(f"[MattStash] Loaded password from sidecar file {sidecar}")
                        return pw
                except Exception:
                    print(f"[MattStash] Failed to read sidecar password file {sidecar}")
            else:
                print(f"[MattStash] Sidecar password file not found at {sidecar}")
        except Exception:
            # Shouldn't really happen, but just in case
            pass
        # 2) Environment variable
        env_pw = os.getenv("KDBX_PASSWORD")
        if env_pw is not None:
            print("[MattStash] Loaded password from environment variable KDBX_PASSWORD")
        else:
            print("[MattStash] Environment variable KDBX_PASSWORD not set")
        return env_pw

    def _ensure_open(self) -> Optional[PyKeePass]:
        if self._kp is not None:
            return self._kp
        if not self.path or not os.path.exists(self.path):
            print(f"[MattStash] KeePass DB file not found at {self.path}")
            return None
        if not self.password:
            print("[MattStash] No password provided (sidecar file or KDBX_PASSWORD missing)")
            return None
        try:
            self._kp = PyKeePass(self.path, password=self.password)
            return self._kp
        except Exception:
            print(f"[MattStash] Found DB at {self.path} and a password, but failed to open (likely wrong key)")
            return None

    # ---- Public API -----------------------------------------------------

    def get(self, title: str, show_password: bool = False) -> Optional[Credential]:
        """
        Fetch a KeePass entry by its Title and return a Credential payload.
        Returns None if the DB/entry cannot be found.
        """
        kp = self._ensure_open()
        if not kp:
            print(f"[MattStash] Unable to open KeePass database at {self.path}")
            return None
        e = kp.find_entries(title=title, first=True)
        if not e:
            print(f"[MattStash] Entry not found: {title}")
            return None
        return Credential(
            credential_name=title,
            username=e.username,
            password=e.password,
            url=e.url,
            notes=e.notes,
            tags=list(e.tags or []),
            show_password=show_password,
        )

    def list(self, show_password: bool = False) -> list[Credential]:
        """
        Return a list of Credential objects for all entries in the KeePass database.
        """
        kp = self._ensure_open()
        if not kp:
            print(f"[MattStash] Unable to open KeePass database at {self.path}")
            return []
        creds = []
        for e in kp.entries:
            creds.append(Credential(
                credential_name=e.title,
                username=e.username,
                password=e.password,
                url=e.url,
                notes=e.notes,
                tags=list(e.tags or []),
                show_password=show_password,
            ))
        return creds

    def hydrate_env(self, mapping: Dict[str, str]) -> None:
        """
        For each mapping 'Title:FIELD' -> ENVVAR, if ENVVAR is unset, read from KeePass.
        FIELD supports:
          - AWS_ACCESS_KEY_ID  -> entry.username
          - AWS_SECRET_ACCESS_KEY -> entry.password
          - otherwise -> custom property with that FIELD name
        """
        kp = self._ensure_open()
        if not kp:
            return
        for src, envname in mapping.items():
            if os.environ.get(envname):
                continue
            base_title, field = src.split(":", 1)
            entry = kp.find_entries(title=base_title, first=True)
            if not entry:
                continue
            if field == "AWS_ACCESS_KEY_ID":
                value = entry.username
            elif field == "AWS_SECRET_ACCESS_KEY":
                value = entry.password
            else:
                value = entry.get_custom_property(field)
            if value:
                os.environ[envname] = value

    def get_s3_client(
            self,
            title: str,
            *,
            region: str = "us-east-1",
            addressing: str = "path",  # "virtual" or "path"
            signature_version: str = "s3v4",
            retries_max_attempts: int = 10,
            verbose: bool = True,
    ):
        """
        Read a KeePass entry and return a configured boto3 S3 client.

        Entry mapping:
          - endpoint_url  <- entry.url  (required)
          - access_key    <- entry.username (required)
          - secret_key    <- entry.password (required)

        Raises ValueError on missing/invalid credential fields.
        """
        cred = self.get(title, show_password=True)
        if cred is None:
            raise ValueError(f"[mattstash] Credential not found: {title}")

        endpoint = _ensure_scheme(cred.url)
        if not endpoint:
            raise ValueError(f"[mattstash] KeePass entry '{title}' has empty URL (S3 endpoint).")

        if not cred.username or not cred.password:
            raise ValueError(f"[mattstash] KeePass entry '{title}' missing username/password.")

        # Lazy imports to avoid hard dependency if caller never uses S3
        try:
            import boto3
            from botocore.config import Config
        except Exception as e:
            raise RuntimeError("[mattstash] boto3/botocore not available") from e

        if verbose:
            print(f"[mattstash] Using endpoint={endpoint}, region={region}, addressing={addressing}")

        cfg = Config(
            s3={"addressing_style": "virtual" if addressing == "virtual" else "path"},
            signature_version=signature_version,
            retries={"max_attempts": retries_max_attempts, "mode": "standard"},
        )

        session = boto3.session.Session()
        return session.client(
            "s3",
            endpoint_url=endpoint,
            region_name=region,
            aws_access_key_id=cred.username,
            aws_secret_access_key=cred.password,
            config=cfg,
        )


# Module-level convenience: mattstash.get("CREDENTIAL NAME")
_default_instance: Optional[MattStash] = None


def get(
        title: str,
        path: Optional[str] = None,
        password: Optional[str] = None,
        show_password: bool = False,
) -> Optional[Credential]:
    global _default_instance
    if path or password or _default_instance is None:
        _default_instance = MattStash(path=path, password=password)
    return _default_instance.get(title, show_password=show_password)


def list_creds(
        path: Optional[str] = None,
        password: Optional[str] = None,
        show_password: bool = False,
) -> list[Credential]:
    global _default_instance
    if path or password or _default_instance is None:
        _default_instance = MattStash(path=path, password=password)
    return _default_instance.list(show_password=show_password)


def get_s3_client(
        title: str,
        *,
        path: Optional[str] = None,
        password: Optional[str] = None,
        region: str = "us-east-1",
        addressing: str = "path",
        signature_version: str = "s3v4",
        retries_max_attempts: int = 10,
        verbose: bool = True,
):
    global _default_instance
    if path or password or _default_instance is None:
        _default_instance = MattStash(path=path, password=password)
    return _default_instance.get_s3_client(
        title,
        region=region,
        addressing=addressing,
        signature_version=signature_version,
        retries_max_attempts=retries_max_attempts,
        verbose=verbose,
    )


# ----------------------------- CLI ------------------------------------


def _serialize_credential(cred: Credential, show_password: bool = False) -> dict:
    """
    Return a JSON-serializable dict for a Credential, honoring show_password.
    """
    if show_password:
        cred.show_password = True
    return cred.as_dict()


def main(argv: Optional[list[str]] = None) -> int:
    """
    Simple CLI:
      - list: show all entries
      - get:  fetch a single entry by title
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

    # get
    p_get = subparsers.add_parser("get", help="Get a single entry by title")
    p_get.add_argument("title", help="KeePass entry title")
    p_get.add_argument("--show-password", action="store_true", help="Show password in output")
    p_get.add_argument("--json", action="store_true", help="Output JSON")

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
    if args.cmd == "list":
        creds = list_creds(path=args.path, password=args.password, show_password=args.show_password)
        if args.json:
            payload = [_serialize_credential(c, show_password=args.show_password) for c in creds]
            print(json.dumps(payload, indent=2))
        else:
            for c in creds:
                pwd_disp = c.password if args.show_password else ("*****" if c.password else None)
                print(f"- {c.credential_name} user={c.username!r} url={c.url!r} pwd={pwd_disp!r} tags={c.tags}")
        return 0

    if args.cmd == "get":
        c = get(args.title, path=args.path, password=args.password, show_password=args.show_password)
        if not c:
            print(f"[mattstash] not found: {args.title}", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(_serialize_credential(c, show_password=args.show_password), indent=2))
        else:
            pwd_disp = c.password if args.show_password else ("*****" if c.password else None)
            print(f"{c.credential_name}")
            print(f"  username: {c.username}")
            print(f"  password: {pwd_disp}")
            print(f"  url:      {c.url}")
            print(f"  tags:     {', '.join(c.tags) if c.tags else ''}")
            if c.notes:
                print("  notes:")
                for line in (c.notes or "").splitlines():
                    print(f"    {line}")
        return 0

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
