"""
mattstash.credential_store
--------------------------
Handles KeePass database operations and credential storage.
"""

import logging
import os
import time
from typing import Dict, List, Optional

from pykeepass import PyKeePass
from pykeepass.entry import Entry

from .models.config import config
from .utils.exceptions import DatabaseAccessError, DatabaseNotFoundError
from .utils.validation import sanitize_error_message

logger = logging.getLogger(__name__)


class CredentialStore:
    """Handles KeePass database operations with optional caching."""

    def __init__(self, db_path: str, password: str, cache_enabled: bool = False, cache_ttl: Optional[int] = None):
        self.db_path = db_path
        self.password = password
        self._kp: Optional[PyKeePass] = None

        # Connection caching settings
        self.cache_enabled = cache_enabled or config.cache_enabled
        self.cache_ttl = cache_ttl if cache_ttl is not None else config.cache_ttl
        self._entry_cache: Dict[str, Entry] = {}
        self._cache_timestamps: Dict[str, float] = {}

    def open(self) -> Optional[PyKeePass]:
        """Open the KeePass database.

        Opens the KeePass database file using the provided password.
        Caches the opened database for subsequent calls.

        Returns:
            PyKeePass instance for database operations

        Raises:
            DatabaseNotFoundError: If database file doesn't exist
            DatabaseAccessError: If password is missing or incorrect

        Example:
            >>> store = CredentialStore("~/.credentials/mattstash.kdbx", "password")
            >>> kp = store.open()
            >>> entries = kp.entries
        """
        if self._kp is not None:
            return self._kp

        if not os.path.exists(self.db_path):
            logger.error("KeePass database file not found")
            raise DatabaseNotFoundError("Database file not found")

        if not self.password:
            logger.error("No password provided for database")
            raise DatabaseAccessError("No password provided for database")

        try:
            self._kp = PyKeePass(self.db_path, password=self.password)
            logger.info("Successfully opened database")
            return self._kp
        except Exception as e:
            sanitized_msg = sanitize_error_message(e, self.db_path)
            logger.error(f"Failed to open database: {sanitized_msg}")
            raise DatabaseAccessError(f"Failed to open database: {sanitized_msg}") from e

    def find_entry_by_title(self, title: str) -> Optional[Entry]:
        """Find a single entry by exact title match with optional caching.

        Args:
            title: Exact title of the entry to find

        Returns:
            Entry object if found, None otherwise

        Example:
            >>> store = CredentialStore(db_path, password, cache_enabled=True)
            >>> entry = store.find_entry_by_title("api-key")
            >>> if entry:
            ...     print(entry.password)
        """
        # Check cache first
        cached = self._get_cached_entry(title)
        if cached is not None:
            return cached

        # Not in cache, fetch from database
        kp = self.open()
        if kp is None:
            return None

        entry = kp.find_entries(title=title, first=True)
        if entry is not None:
            self._cache_entry(title, entry)

        return entry

    def find_entries_by_prefix(self, prefix: str) -> List[Entry]:
        """Find all entries whose titles start with the given prefix."""
        kp = self.open()
        if kp is None:
            return []
        return [e for e in kp.entries if e.title and e.title.startswith(prefix)]

    def create_entry(self, title: str, username: str = "", password: str = "", url: str = "", notes: str = "") -> Entry:
        """Create a new entry in the database."""
        kp = self.open()
        if kp is None:
            raise DatabaseAccessError("Unable to open database")
        entry = kp.add_entry(kp.root_group, title=title, username=username, password=password, url=url, notes=notes)
        return entry

    def _get_cached_entry(self, title: str) -> Optional[Entry]:
        """Get entry from cache if valid.

        Args:
            title: Title of the entry to retrieve

        Returns:
            Cached entry if valid, None otherwise
        """
        if not self.cache_enabled:
            return None

        if title in self._entry_cache:
            timestamp = self._cache_timestamps.get(title, 0.0)
            if time.time() - timestamp < self.cache_ttl:
                logger.debug(f"Cache hit for '{title}'")
                return self._entry_cache[title]
            else:
                # Expired, remove from cache
                logger.debug(f"Cache expired for '{title}'")
                del self._entry_cache[title]
                del self._cache_timestamps[title]

        return None

    def _cache_entry(self, title: str, entry: Entry) -> None:
        """Cache an entry with current timestamp.

        Args:
            title: Title of the entry
            entry: Entry object to cache
        """
        if self.cache_enabled:
            self._entry_cache[title] = entry
            self._cache_timestamps[title] = time.time()
            logger.debug(f"Cached entry '{title}'")

    def clear_cache(self) -> None:
        """Clear all cached entries."""
        self._entry_cache.clear()
        self._cache_timestamps.clear()
        logger.debug("Entry cache cleared")

    def save(self) -> None:
        """Save changes to the database and clear cache."""
        if self._kp:
            self._kp.save()
            self.clear_cache()  # Invalidate cache on save
            logger.debug("Database saved successfully")

    def delete_entry(self, entry: Entry) -> bool:
        """Delete an entry from the database."""
        try:
            kp = self.open()
            if kp is None:
                return False
            kp.delete_entry(entry)
            self.save()
            return True
        except Exception as e:
            logger.error(f"Failed to delete entry: {e}")
            return False

    def get_all_entries(self) -> List[Entry]:
        """Get all entries from the database."""
        kp = self.open()
        if kp is None:
            return []
        return list(kp.entries)
