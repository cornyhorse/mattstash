"""
mattstash.credential_store
--------------------------
Handles KeePass database operations and credential storage.
"""

import contextlib
import hashlib
import logging
import os
import secrets
import stat
import time
from typing import Dict, List, Optional, Tuple

from pykeepass import PyKeePass
from pykeepass.entry import Entry

from .models.config import config
from .utils.exceptions import DatabaseAccessError, DatabaseNotFoundError
from .utils.fileops import fsync_directory, match_owner
from .utils.logging_config import security_warning
from .utils.validation import sanitize_error_message

logger = logging.getLogger(__name__)


class CredentialStore:
    """Handles KeePass database operations with optional caching."""

    def __init__(self, db_path: str, password: str, cache_enabled: bool = False, cache_ttl: Optional[int] = None):
        #: The path as given. It is followed (symlinks included) every time it is read, so a retargeted symlink or a
        #: swapped Kubernetes Secret volume (``..data`` -> ``..<timestamp>``) is noticed.
        self.db_path = db_path
        self.password = password
        self._kp: Optional[PyKeePass] = None
        #: What ``db_path`` resolved to when the database was opened; saves go to this file (so a symlinked database
        #: stays a symlink) and a caller compares it with the current resolution to detect a retarget.
        self.real_path = db_path
        # (inode, mtime_ns, size, header fingerprint) of the file as last read/written by us. pykeepass saves by
        # renaming a temp file over the target (the inode alternates between two values, mtime has tick
        # granularity and sizes often repeat), so the signature also hashes the start of the file: the KDBX header
        # holds a master seed and IV that are rotated on every save.
        self._file_sig: Optional[Tuple[int, int, int, bytes]] = None

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
            raise DatabaseNotFoundError(f"Database file not found: {self.db_path}. Create one with 'mattstash setup'.")

        if not self.password:
            logger.error("No password provided for database")
            raise DatabaseAccessError("No password provided for database")

        self._warn_if_insecure_permissions()
        try:
            # Take the signature BEFORE reading: if another writer replaces the file while we
            # decrypt, the next has_file_changed() correctly reports a change.
            sig = self._current_signature()
            self.real_path = os.path.realpath(self.db_path)
            self._kp = PyKeePass(self.real_path, password=self.password)
            self._file_sig = sig
            logger.info("Successfully opened database")
            return self._kp
        except Exception as e:
            sanitized_msg = sanitize_error_message(e, self.db_path)
            logger.error(f"Failed to open database: {sanitized_msg}")
            raise DatabaseAccessError(f"Failed to open database: {sanitized_msg}") from e

    def _current_signature(self) -> Optional[Tuple[int, int, int, bytes]]:
        try:
            with open(self.db_path, "rb") as f:
                st = os.fstat(f.fileno())
                head = hashlib.blake2b(f.read(512), digest_size=8).digest()
        except OSError:
            return None
        return (st.st_ino, st.st_mtime_ns, st.st_size, head)

    def _warn_if_insecure_permissions(self) -> None:
        """Warn when the database file is readable/writable by group or others."""
        try:
            mode = os.stat(self.db_path).st_mode
        except OSError:  # pragma: no cover
            return
        if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
            security_warning(
                f"Database file has insecure permissions: {oct(stat.S_IMODE(mode))}. "
                "Should be 0600 (owner read/write only)."
            )

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

        # Exact match in Python: pykeepass builds an XPath from the title, so quotes in a
        # title would break out of the query (see docs/security-review.md H-1).
        entry = next((e for e in kp.entries if e.title == title), None)
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
        # Build the entry directly: PyKeePass.add_entry() runs an XPath duplicate check that
        # breaks on (and can be steered by) quotes in the title.
        entry = Entry(title=title, username=username, password=password, url=url, notes=notes, kp=kp)
        kp.root_group.append(entry)
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
        """Save changes to the database and clear cache.

        The new file is written under a unique temporary name in the database's directory (``0600`` from the first
        byte, the existing owner/group and mode afterwards), flushed to disk and renamed over the database: readers
        and crashes see the old file or the new one, never a partial one. (pykeepass's own temp name is
        ``<stem>.tmp``, which two databases sharing a stem would fight over.)

        Raises:
            DatabaseAccessError: the database is not open, or the file system refused the write (the existing file is
                left as it was).
        """
        if self._kp is None:
            # Silently doing nothing would let callers believe a change was stored.
            raise DatabaseAccessError("Database is not open; nothing was saved")
        target = self.real_path
        directory = os.path.dirname(target) or "."
        try:
            reference: Optional[os.stat_result] = os.stat(target)
        except OSError:
            reference = None
        mode = stat.S_IMODE(reference.st_mode) if reference is not None else 0o600
        staged = os.path.join(directory, f".{os.path.basename(target)}.{secrets.token_hex(6)}.new")
        # pykeepass writes "<staged without its last suffix>.tmp" and then moves that onto ``staged``
        pk_tmp = os.path.splitext(staged)[0] + ".tmp"
        try:
            fd = os.open(pk_tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            with contextlib.suppress(OSError):
                os.chmod(pk_tmp, 0o600)  # not subject to the umask: a 0400 temp file could not be written below
            self._kp.save(filename=staged)
            with contextlib.suppress(OSError):  # pragma: no cover - non-POSIX
                os.chmod(staged, mode)
            if reference is not None:
                match_owner(reference, staged)
            fd = os.open(staged, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(staged, target)
            fsync_directory(directory)
        except OSError as exc:
            for leftover in (pk_tmp, staged):
                with contextlib.suppress(OSError):
                    os.remove(leftover)
            raise DatabaseAccessError(f"Could not save the database: {exc.strerror or exc}") from exc
        except BaseException:
            for leftover in (pk_tmp, staged):
                with contextlib.suppress(OSError):
                    os.remove(leftover)
            raise
        self._file_sig = self._current_signature()
        self.clear_cache()  # Invalidate cache on save
        logger.debug("Database saved successfully")

    def change_password(self, new_password: str) -> None:
        """Re-key the open database with ``new_password`` and save it.

        If saving fails the old password is restored in memory and the file is left as it was.
        """
        kp = self.open()
        if kp is None:  # pragma: no cover - open() raises instead
            raise DatabaseAccessError("Unable to open database")
        old_password = self.password
        kp.password = new_password
        try:
            self.save()
        except BaseException:
            kp.password = old_password
            raise
        self.password = new_password

    def has_file_changed(self) -> bool:
        """Check if the KDBX file has been modified externally since last open/save.

        Returns:
            True if the file's identity (inode, mtime, size) differs from the last
            recorded one. A missing file is reported as unchanged.
        """
        current = self._current_signature()
        if current is None:
            return False
        return current != self._file_sig

    def reload(self) -> Optional[PyKeePass]:
        """Close and reopen the database from disk.

        Returns:
            PyKeePass instance after reopening.

        Raises:
            DatabaseNotFoundError: If database file doesn't exist.
            DatabaseAccessError: If password is incorrect.
        """
        self._kp = None
        self.clear_cache()
        logger.info("Reloading database from disk")
        return self.open()

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
