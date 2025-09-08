"""
mattstash.credential_store
--------------------------
Handles KeePass database operations and credential storage.
"""

import os
import logging
from typing import Optional, List
from pykeepass import PyKeePass
from pykeepass.entry import Entry

from .config import config
from .exceptions import DatabaseNotFoundError, DatabaseAccessError, CredentialNotFoundError

logger = logging.getLogger(__name__)


class CredentialStore:
    """Handles KeePass database operations."""

    def __init__(self, db_path: str, password: str):
        self.db_path = db_path
        self.password = password
        self._kp: Optional[PyKeePass] = None

    def open(self) -> Optional[PyKeePass]:
        """Open the KeePass database."""
        if self._kp is not None:
            return self._kp

        if not os.path.exists(self.db_path):
            logger.error(f"KeePass DB file not found at {self.db_path}")
            raise DatabaseNotFoundError(f"Database file not found: {self.db_path}")

        if not self.password:
            logger.error("No password provided for database")
            raise DatabaseAccessError("No password provided for database")

        try:
            self._kp = PyKeePass(self.db_path, password=self.password)
            logger.info(f"Successfully opened database at {self.db_path}")
            return self._kp
        except Exception as e:
            logger.error(f"Failed to open database: {e}")
            raise DatabaseAccessError(f"Failed to open database: {e}")

    def find_entry_by_title(self, title: str) -> Optional[Entry]:
        """Find a single entry by exact title match."""
        kp = self.open()
        return kp.find_entries(title=title, first=True)

    def find_entries_by_prefix(self, prefix: str) -> List[Entry]:
        """Find all entries whose titles start with the given prefix."""
        kp = self.open()
        return [e for e in kp.entries if e.title and e.title.startswith(prefix)]

    def create_entry(self, title: str, username: str = "", password: str = "",
                    url: str = "", notes: str = "") -> Entry:
        """Create a new entry in the database."""
        kp = self.open()
        entry = kp.add_entry(
            kp.root_group,
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes
        )
        return entry

    def save(self):
        """Save changes to the database."""
        if self._kp:
            self._kp.save()
            logger.debug("Database saved successfully")

    def delete_entry(self, entry: Entry) -> bool:
        """Delete an entry from the database."""
        try:
            kp = self.open()
            kp.delete_entry(entry)
            self.save()
            return True
        except Exception as e:
            logger.error(f"Failed to delete entry: {e}")
            return False

    def get_all_entries(self) -> List[Entry]:
        """Get all entries from the database."""
        kp = self.open()
        return list(kp.entries)
