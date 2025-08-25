"""
mattstash.core
--------------
KeePass-backed secrets accessor + optional boto3 S3 client helper.
"""

from __future__ import annotations

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from pykeepass import PyKeePass

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

DEFAULT_KDBX_PATH = os.path.expanduser("~/.credentials/k8s-db.kdbx")


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
      - default path of ~/.credentials/k8s-db.kdbx (override via ctor)
      - password sources: explicit arg, then sidecar file next to the DB named '.k8s-db.txt', then KDBX_PASSWORD environment variable
      - generic get(title) -> Credential
      - optional env hydration (mapping of keepass 'title:FIELD' -> ENVVAR)
    """

    def __init__(self, path: Optional[str] = None, password: Optional[str] = None):
        self.path = os.path.expanduser(path or DEFAULT_KDBX_PATH)
        self.password = password or self._resolve_password()
        self._kp: Optional[PyKeePass] = None

    def _resolve_password(self) -> Optional[str]:
        # 1) Sidecar plaintext file next to the DB (e.g., ~/.credentials/.k8s-db.txt)
        sidecar = os.path.join(os.path.dirname(self.path), ".k8s-db.txt")
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
        addressing: str = "path",            # "virtual" or "path"
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