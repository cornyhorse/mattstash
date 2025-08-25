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
from urllib.parse import urlparse

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
    "list_creds",
    "get_s3_client",
    "put",
    "delete",
    "list_versions",
    "get_db_url",
]

DEFAULT_KDBX_PATH = os.path.expanduser("~/.config/mattstash/mattstash.kdbx")

# Sidecar plaintext file name stored next to the KDBX DB
DEFAULT_KDBX_SIDECAR_BASENAME = ".mattstash.txt"

# Zero-padding width for version strings
PAD_WIDTH = 10


@dataclass
class Credential:
    """
    Container for a KeePass entry's commonly used fields.
    The 'notes' field is used for comments/notes associated with the credential.
    """
    credential_name: str
    username: Optional[str]
    password: Optional[str]
    url: Optional[str]
    notes: Optional[str]  # Used for comments/notes
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
    # -------------------- SQLAlchemy / psycopg helpers --------------------

    def _parse_host_port(self, endpoint: Optional[str]) -> tuple[str, int]:
        """Parse host and port from an endpoint string.
        Accepts either a raw `host:port` or a URL like `scheme://host:port/...`.
        Raises ValueError if the port is missing or invalid.
        """
        if not endpoint:
            raise ValueError("[mattstash] Empty database endpoint URL")
        ep = endpoint.strip()
        host = None
        port = None
        if "://" in ep:
            parsed = urlparse(ep)
            netloc = parsed.netloc or parsed.path  # some urlparse variants put everything in path for odd inputs
            if ":" not in netloc:
                raise ValueError("[mattstash] Database endpoint must include a port (e.g., host:5432)")
            host, port_str = netloc.split("@", 1)[-1].rsplit(":", 1) if "@" in netloc else netloc.rsplit(":", 1)
            if not port_str.isdigit():
                raise ValueError("[mattstash] Invalid database port in endpoint")
            port = int(port_str)
        else:
            if ":" not in ep:
                raise ValueError("[mattstash] Database endpoint must include a port (e.g., host:5432)")
            host, port_str = ep.rsplit(":", 1)
            if not port_str.isdigit():
                raise ValueError("[mattstash] Invalid database port in endpoint")
            port = int(port_str)
        host = host.strip("/")
        return host, port

    def get_db_url(
            self,
            title: str,
            *,
            driver: Optional[str] = None,
            mask_password: bool = True,
            mask_style: str = "stars",  # "stars" -> user:*****, "omit" -> user (no password section)
            database: Optional[str] = None,
            sslmode_override: Optional[str] = None,
    ) -> str:
        """Construct a SQLAlchemy URL from a KeePass entry.

        Mapping:
          - entry.username -> user
          - entry.password -> password
          - entry.url      -> host:port (required; raises if no port)
          - custom property `database` or `dbname` -> database name (required, unless `database` arg is provided)
          - optional custom property `sslmode` -> added as query param (can be overridden with sslmode_override)
        Additional:
          - database: can be provided explicitly and will override custom props.
          - sslmode_override: can override the custom property.
          - driver: optional driver suffix (e.g. "psycopg"); if provided the URL is `postgresql+{driver}://...`,
            otherwise `postgresql://...`.
          - mask_password:
              True  -> do not reveal the real password (use mask_style behavior)
              False -> include the real password when present
          - mask_style:
              "stars" -> include `:*****` after the username (API default)
              "omit"  -> omit the password entirely and render only `user@` (CLI default)

        Examples:
          - API default (masked stars, no driver):    `postgresql://user:*****@host:5432/db`
          - CLI masked default (omit, with driver):   `postgresql+psycopg://user@host:5432/db`
          - Unmasked with driver:                     `postgresql+psycopg://user:pw@host:5432/db`
        """
        cred = self.get(title, show_password=True)
        if cred is None:
            raise ValueError(f"[mattstash] Credential not found: {title}")
        # If `cred` is a dict (simple secret), this is not a full DB cred
        if isinstance(cred, dict):
            raise ValueError("[mattstash] Entry is a simple secret and cannot be used for a DB connection")

        host, port = self._parse_host_port(cred.url)

        kp = self._ensure_open()
        if not kp:
            raise ValueError("[mattstash] Unable to open KeePass database")
        entry = kp.find_entries(title=title, first=True)
        if not entry:
            # If versioning was used and latest resolved above, we still need the entry object to read custom props
            # Attempt to resolve latest versioned entry
            prefix = f"{title}@"
            candidates = [e for e in kp.entries if e.title and e.title.startswith(prefix)]
            if candidates:
                entry = max(candidates, key=lambda e: int(e.title[len(prefix):]))
            else:
                raise ValueError(f"[mattstash] Credential entry not found: {title}")

        dbname = database or entry.get_custom_property("database") or entry.get_custom_property("dbname")
        if not dbname:
            raise ValueError("[mattstash] Missing database name. Provide --database/`database=` or set custom property 'database'/'dbname' on the credential.")

        sslmode = sslmode_override if sslmode_override is not None else entry.get_custom_property("sslmode")

        dialect = "postgresql" + (f"+{driver}" if driver else "")
        user = cred.username or ""
        pwd = cred.password or ""

        if mask_password:
            if mask_style == "omit":
                userinfo = user
            else:  # "stars" (default)
                if pwd:
                    userinfo = f"{user}:*****"
                else:
                    userinfo = user
        else:
            # include the real password if available
            if pwd:
                userinfo = f"{user}:{pwd}"
            else:
                userinfo = user

        base = f"{dialect}://{userinfo}@{host}:{port}/{dbname}"
        if sslmode:
            base = f"{base}?sslmode={sslmode}"
        return base

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
                        print(f"[MattStash] Loaded password from sidecar file {sidecar}", file=sys.stderr)
                        return pw
                except Exception:
                    print(f"[MattStash] Failed to read sidecar password file {sidecar}", file=sys.stderr)
            else:
                print(f"[MattStash] Sidecar password file not found at {sidecar}", file=sys.stderr)
        except Exception:
            # Shouldn't really happen, but just in case
            pass
        # 2) Environment variable
        env_pw = os.getenv("KDBX_PASSWORD")
        if env_pw is not None:
            print("[MattStash] Loaded password from environment variable KDBX_PASSWORD", file=sys.stderr)
        else:
            print("[MattStash] Environment variable KDBX_PASSWORD not set", file=sys.stderr)
        return env_pw

    def _ensure_open(self) -> Optional[PyKeePass]:
        if self._kp is not None:
            return self._kp
        if not self.path or not os.path.exists(self.path):
            print(f"[MattStash] KeePass DB file not found at {self.path}", file=sys.stderr)
            return None
        if not self.password:
            print("[MattStash] No password provided (sidecar file or KDBX_PASSWORD missing)", file=sys.stderr)
            return None
        try:
            self._kp = PyKeePass(self.path, password=self.password)
            return self._kp
        except Exception:
            print(f"[MattStash] Found DB at {self.path} and a password, but failed to open (likely wrong key)",
                  file=sys.stderr)
            return None

    def _is_simple_secret(self, e) -> bool:
        """
        A 'simple secret' mimics credstash semantics: only the password field is used.
        Consider it simple if username and url are empty/None and password is non-empty.
        Notes/comments are allowed and do not change this classification. Tags are ignored.
        """

        def _empty(v):
            return v is None or (isinstance(v, str) and v.strip() == "")

        try:
            # Treat entries with only password set (regardless of notes) as simple secrets
            return (not _empty(e.password)) and _empty(e.username) and _empty(e.url)
        except Exception:
            return False

    # ---- Public API -----------------------------------------------------

    def get(self, title: str, show_password: bool = False, version: Optional[int] = None) -> Optional[Credential]:
        """
        Fetch a KeePass entry by its Title (optionally versioned) and return a Credential payload.
        Returns None if the DB/entry cannot be found.
        If versioned, looks for entries named <title>@<version>.
        If version is None, finds the highest version (if any), else falls back to unversioned.
        """
        kp = self._ensure_open()
        if not kp:
            print(f"[MattStash] Unable to open KeePass database at {self.path}", file=sys.stderr)
            return None
        entry_title = title
        if version is not None:
            vstr = str(int(version)).zfill(PAD_WIDTH)
            entry_title = f"{title}@{vstr}"
            e = kp.find_entries(title=entry_title, first=True)
            if not e:
                print(f"[MattStash] Entry not found: {entry_title}", file=sys.stderr)
                return None
            # Simple-secret mode (credstash-like): only password is populated
            if self._is_simple_secret(e):
                value = e.password if show_password else ("*****" if e.password else None)
                return {"name": title, "version": vstr, "value": value, "notes": e.notes if e.notes else None}
            return Credential(
                credential_name=title,
                username=e.username,
                password=e.password,
                url=e.url,
                notes=e.notes,
                tags=list(e.tags or []),
                show_password=show_password,
            )
        # No version specified: scan for versioned entries
        prefix = f"{title}@"
        candidates = [e for e in kp.entries if e.title and e.title.startswith(prefix)]
        if candidates:
            # Find max version
            def extract_ver(e):
                try:
                    return int(e.title[len(prefix):])
                except Exception:
                    return -1

            candidates = [(extract_ver(e), e) for e in candidates if extract_ver(e) >= 0]
            if not candidates:
                print(f"[MattStash] No valid versioned entries found for {title}", file=sys.stderr)
                return None
            max_ver, e = max(candidates, key=lambda t: t[0])
            vstr = str(max_ver).zfill(PAD_WIDTH)
            # Simple-secret mode (credstash-like): only password is populated
            if self._is_simple_secret(e):
                value = e.password if show_password else ("*****" if e.password else None)
                return {"name": title, "version": vstr, "value": value, "notes": e.notes if e.notes else None}
            return Credential(
                credential_name=title,
                username=e.username,
                password=e.password,
                url=e.url,
                notes=e.notes,
                tags=list(e.tags or []),
                show_password=show_password,
            )
        # Fallback to unversioned
        e = kp.find_entries(title=title, first=True)
        if not e:
            print(f"[MattStash] Entry not found: {title}", file=sys.stderr)
            return None
        if self._is_simple_secret(e):
            value = e.password if show_password else ("*****" if e.password else None)
            return {"name": title, "version": None, "value": value, "notes": e.notes if e.notes else None}
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
            print(f"[MattStash] Unable to open KeePass database at {self.path}", file=sys.stderr)
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

    def put(
            self,
            title: str,
            *,
            value: Optional[str] = None,
            username: Optional[str] = None,
            password: Optional[str] = None,
            url: Optional[str] = None,
            notes: Optional[str] = None,
            tags: Optional[list[str]] = None,
            version: Optional[int] = None,
            autoincrement: bool = True,
    ):
        """
        Create or update an entry.

        Modes:
          - Simple (credstash-like): only 'value' is provided -> stored in password field.
            Returns {"name": <title>, "version": <version>, "value": <masked or plain per show_password=False default>}.
          - Full credential: any of username/password/url/notes/tags provided -> stored accordingly.
            Returns a Credential object.

        If versioning is used, the entry is stored as <title>@<version> (zero-padded to 12 digits).
        """
        kp = self._ensure_open()
        if not kp:
            print(f"[MattStash] Unable to open KeePass database at {self.path}", file=sys.stderr)
            return None

        # Versioning logic
        entry_title = title
        vstr = None
        if version is not None or autoincrement:
            # Find max version if needed
            prefix = f"{title}@"
            if version is None and autoincrement:
                # Scan for all <title>@NNNNNNNNNNNN entries, get max
                candidates = [e for e in kp.entries if e.title and e.title.startswith(prefix)]
                max_ver = 0
                for e in candidates:
                    try:
                        v = int(e.title[len(prefix):])
                        if v > max_ver:
                            max_ver = v
                    except Exception:
                        continue
                new_ver = max_ver + 1
                vstr = str(new_ver).zfill(PAD_WIDTH)
            elif version is not None:
                vstr = str(int(version)).zfill(PAD_WIDTH)
            else:
                # Should not happen, fallback
                vstr = str(1).zfill(PAD_WIDTH)
            entry_title = f"{title}@{vstr}"
        # Find or create entry
        e = kp.find_entries(title=entry_title, first=True)
        if e is None:
            grp = kp.root_group
            e = kp.add_entry(grp, title=entry_title, username="", password="", url="", notes="")

        # Decide mode
        simple_mode = value is not None and username is None and password is None and url is None and (
                tags is None or len(tags) == 0)

        if simple_mode:
            e.username = ""
            e.url = ""
            # Only set notes if provided, otherwise leave as is (don't wipe)
            if notes is not None:
                e.notes = notes
            e.password = value
            if tags is not None:
                try:
                    e.tags = set(tags)
                except Exception:
                    for t in (tags or []):
                        try:
                            e.add_tag(t)
                        except Exception:
                            pass
            kp.save()
            # Return credstash-like structure (masked by default), include notes
            return {
                "name": title,
                "version": vstr,
                "value": "*****" if (value is not None) else None,
                "notes": e.notes if e.notes else None,
            }

        # Full credential mode
        if username is not None:
            e.username = username
        if password is not None:
            e.password = password
        if url is not None:
            e.url = url
        if notes is not None:
            e.notes = notes
        if tags is not None:
            try:
                e.tags = set(tags)
            except Exception:
                for t in list(e.tags or []):
                    try:
                        e.remove_tag(t)
                    except Exception:
                        pass
                for t in tags:
                    try:
                        e.add_tag(t)
                    except Exception:
                        pass

        kp.save()
        return Credential(
            credential_name=title,
            username=e.username,
            password=e.password,
            url=e.url,
            notes=e.notes,
            tags=list(e.tags or []),
            show_password=False,
        )

    def list_versions(self, title: str) -> list[str]:
        """
        List all versions (zero-padded strings) for a given title, sorted ascending.
        """
        kp = self._ensure_open()
        if not kp:
            print(f"[MattStash] Unable to open KeePass database at {self.path}", file=sys.stderr)
            return []
        prefix = f"{title}@"
        versions = []
        for e in kp.entries:
            if e.title and e.title.startswith(prefix):
                vstr = e.title[len(prefix):]
                if vstr.isdigit() and len(vstr) == PAD_WIDTH:
                    versions.append(vstr)
        versions.sort()
        return versions

    def delete(self, title: str) -> bool:
        """
        Delete an entry by title. Returns True if deleted, False otherwise.
        """
        kp = self._ensure_open()
        if not kp:
            print(f"[MattStash] Unable to open KeePass database at {self.path}", file=sys.stderr)
            return False
        e = kp.find_entries(title=title, first=True)
        if not e:
            print(f"[MattStash] Entry not found: {title}", file=sys.stderr)
            return False
        try:
            kp.delete_entry(e)
            kp.save()
            return True
        except Exception as ex:
            print(f"[MattStash] Failed to delete entry '{title}': {ex}", file=sys.stderr)
            return False

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


def get_db_url(
        title: str,
        *,
        path: Optional[str] = None,
        password: Optional[str] = None,
        driver: Optional[str] = None,
        mask_password: bool = True,
        mask_style: str = "stars",
        database: Optional[str] = None,
        sslmode_override: Optional[str] = None,
) -> str:
    global _default_instance
    if path or password or _default_instance is None:
        _default_instance = MattStash(path=path, password=password)
    return _default_instance.get_db_url(
        title,
        driver=driver,
        mask_password=mask_password,
        mask_style=mask_style,
        database=database,
        sslmode_override=sslmode_override,
    )


def get(
        title: str,
        path: Optional[str] = None,
        password: Optional[str] = None,
        show_password: bool = False,
        version: Optional[int] = None,
) -> Optional[Credential]:
    global _default_instance
    if path or password or _default_instance is None:
        _default_instance = MattStash(path=path, password=password)
    return _default_instance.get(title, show_password=show_password, version=version)


def list_creds(
        path: Optional[str] = None,
        password: Optional[str] = None,
        show_password: bool = False,
) -> list[Credential]:
    global _default_instance
    if path or password or _default_instance is None:
        _default_instance = MattStash(path=path, password=password)
    return _default_instance.list(show_password=show_password)


def put(
        title: str,
        *,
        path: Optional[str] = None,
        db_password: Optional[str] = None,
        value: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        url: Optional[str] = None,
        notes: Optional[str] = None,
        comment: Optional[str] = None,
        tags: Optional[list[str]] = None,
        version: Optional[int] = None,
        autoincrement: bool = True,
):
    """
    Create or update an entry. If only 'value' is provided, store it in the password field (credstash-like).
    Otherwise, update fields provided and return a Credential.
    Supports versioning.
    The 'notes' or 'comment' parameter can be used to set notes/comments for the credential.
    """
    global _default_instance
    if path or db_password or _default_instance is None:
        _default_instance = MattStash(path=path, password=db_password)
    # Prefer notes if provided, else comment, else None
    notes_val = notes if notes is not None else comment
    return _default_instance.put(
        title,
        value=value,
        username=username,
        password=password,
        url=url,
        notes=notes_val,
        tags=tags,
        version=version,
        autoincrement=autoincrement,
    )


def list_versions(
        title: str,
        path: Optional[str] = None,
        password: Optional[str] = None,
) -> list[str]:
    """
    List all versions (zero-padded strings) for a given title, sorted ascending.
    """
    global _default_instance
    if path or password or _default_instance is None:
        _default_instance = MattStash(path=path, password=password)
    return _default_instance.list_versions(title)


def delete(
        title: str,
        path: Optional[str] = None,
        password: Optional[str] = None,
) -> bool:
    """
    Delete an entry by title. Returns True if deleted, False otherwise.
    """
    global _default_instance
    if path or password or _default_instance is None:
        _default_instance = MattStash(path=path, password=password)
    return _default_instance.delete(title)


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
                print(json.dumps(_serialize_credential(result, show_password=False), indent=2))
        else:
            print(f"{args.title}: OK")
        return 0

    if args.cmd == "list":
        creds = list_creds(path=args.path, password=args.password, show_password=args.show_password)
        if args.json:
            payload = [_serialize_credential(c, show_password=args.show_password) for c in creds]
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
                print(json.dumps(_serialize_credential(c, show_password=args.show_password), indent=2))
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
