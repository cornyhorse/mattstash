"""
mattstash.core.mattstash
------------------------
Refactored MattStash class that orchestrates components.
"""

import os
from typing import Optional, Dict, List, Any

from ..models.config import config
from ..models.credential import Credential, CredentialResult
from ..credential_store import CredentialStore
from ..builders.db_url import DatabaseUrlBuilder
from ..builders.s3_client import S3ClientBuilder
from ..utils.logging_config import get_logger
from .bootstrap import DatabaseBootstrapper
from .password_resolver import PasswordResolver
from .entry_manager import EntryManager

logger = get_logger(__name__)


class MattStash:
    """
    Simple KeePass accessor with:
      - default path of ~/.credentials/mattstash.kdbx (override via ctor)
      - password sources: explicit arg, then sidecar file next to the DB named '.mattstash.txt', then KDBX_PASSWORD environment variable
      - generic get(title) -> Credential
      - optional env hydration (mapping of keepass 'title:FIELD' -> ENVVAR)
    """

    def __init__(self, path: Optional[str] = None, password: Optional[str] = None):
        self.path = os.path.expanduser(path or config.default_db_path)

        # Initialize components
        self._bootstrapper = DatabaseBootstrapper(self.path)
        self._password_resolver = PasswordResolver(self.path)

        # Create DB + sidecar if both are missing (credstash-like bootstrap)
        self._bootstrapper.bootstrap_if_missing()

        # Resolve password
        self.password = password or self._password_resolver.resolve_password()

        # Initialize credential store and other components
        self._credential_store: Optional[CredentialStore] = None
        self._entry_manager: Optional[EntryManager] = None

        # Initialize helper components for backward compatibility
        self._db_url_builder = DatabaseUrlBuilder(self)
        self._s3_client_builder = S3ClientBuilder(self)

    def _ensure_initialized(self) -> bool:
        """Ensure the credential store and entry manager are initialized."""
        if self._credential_store is None:
            if not self.password:
                logger.error("No password provided (sidecar file or KDBX_PASSWORD missing)")
                return False

            try:
                self._credential_store = CredentialStore(self.path, self.password)
                kp = self._credential_store.open()
                self._entry_manager = EntryManager(kp)
                return True
            except Exception as e:
                logger.error(f"Failed to initialize: {e}")
                return False
        return True

    # ---- Public API -----------------------------------------------------

    def get(self, title: str, show_password: bool = False, version: Optional[int] = None) -> Optional[CredentialResult]:
        """
        Fetch a KeePass entry by its Title (optionally versioned) and return a Credential payload.
        Returns None if the DB/entry cannot be found.
        """
        if not self._ensure_initialized():
            return None
        assert self._entry_manager is not None
        return self._entry_manager.get_entry(title, show_password, version)

    def list(self, show_password: bool = False) -> List[Credential]:
        """
        Return a list of Credential objects for all entries in the KeePass database.
        """
        if not self._ensure_initialized():
            return []
        assert self._entry_manager is not None
        return self._entry_manager.list_entries(show_password)

    def put(
            self,
            title: str,
            *,
            value: Optional[str] = None,
            username: Optional[str] = None,
            password: Optional[str] = None,
            url: Optional[str] = None,
            notes: Optional[str] = None,
            tags: Optional[List[str]] = None,
            version: Optional[int] = None,
            autoincrement: bool = True,
    ) -> Optional[CredentialResult]:
        """
        Create or update an entry.

        Modes:
          - Simple (credstash-like): only 'value' is provided -> stored in password field.
          - Full credential: any of username/password/url/notes/tags provided -> stored accordingly.

        If versioning is used, the entry is stored as <title>@<version> (zero-padded).
        """
        if not self._ensure_initialized():
            return None
        assert self._entry_manager is not None

        return self._entry_manager.put_entry(
            title,
            value=value,
            username=username,
            password=password,
            url=url,
            notes=notes,
            tags=tags,
            version=version,
            autoincrement=autoincrement
        )

    def list_versions(self, title: str) -> List[str]:
        """
        List all versions (zero-padded strings) for a given title, sorted ascending.
        """
        if not self._ensure_initialized():
            return []
        assert self._entry_manager is not None
        return self._entry_manager.list_versions(title)

    def delete(self, title: str) -> bool:
        """
        Delete an entry by title. Returns True if deleted, False otherwise.
        """
        if not self._ensure_initialized():
            return False
        assert self._entry_manager is not None
        return self._entry_manager.delete_entry(title)

    def hydrate_env(self, mapping: Dict[str, str]) -> None:
        """
        For each mapping 'Title:FIELD' -> ENVVAR, if ENVVAR is unset, read from KeePass.
        FIELD supports:
          - AWS_ACCESS_KEY_ID  -> entry.username
          - AWS_SECRET_ACCESS_KEY -> entry.password
          - otherwise -> custom property with that FIELD name
        """
        if not self._ensure_initialized():
            return
        assert self._credential_store is not None

        kp = self._credential_store.open()
        if kp is None:
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

    # ---- Delegated functionality to helper classes ----

    def get_db_url(self, *args: Any, **kwargs: Any) -> str:
        """Delegate to DatabaseUrlBuilder."""
        return self._db_url_builder.build_url(*args, **kwargs)

    def get_s3_client(self, *args: Any, **kwargs: Any) -> Any:
        """Delegate to S3ClientBuilder."""
        return self._s3_client_builder.create_client(*args, **kwargs)

    def _parse_host_port(self, endpoint: Optional[str]) -> tuple[str, int]:
        """Delegate to DatabaseUrlBuilder for backward compatibility with tests."""
        return self._db_url_builder._parse_host_port(endpoint)
