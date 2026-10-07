"""
mattstash.core.mattstash
------------------------
MattStash class that orchestrates the store, entry manager and locking.

Concurrency model
~~~~~~~~~~~~~~~~~
* A ``threading.RLock`` makes one ``MattStash`` object safe to share between threads.
* Writes additionally hold a cross-process advisory lock (``<db>.lock``) for the whole
  read-modify-write cycle. Inside it the database is re-read if another writer changed
  the file, so concurrent writers (CLI + server, several processes) cannot overwrite each
  other's changes.
* If anything fails inside a write, the in-memory copy is discarded and re-read from
  disk on next use, so memory never diverges from what is actually stored.
* Reads never take the file lock (saves are atomic renames) but do pick up external
  changes automatically.

Errors
~~~~~~
A missing secret is reported as ``None``/``False``. Problems with the database itself
raise ``DatabaseNotFoundError`` / ``DatabaseAccessError`` / ``DatabaseLockError`` -- they
are never disguised as "not found".
"""

import contextlib
import os
import threading
import time
import weakref
from collections.abc import Iterable, Iterator, Mapping
from datetime import UTC, datetime
from typing import Any, Dict, List, Optional

from ..builders.db_url import DatabaseUrlBuilder
from ..builders.s3_client import S3ClientBuilder
from ..credential_store import CredentialStore
from ..models.config import config
from ..models.credential import Credential, CredentialResult
from ..utils.exceptions import (
    CredentialNotFoundError,
    DatabaseAccessError,
    DatabaseExistsError,
    DatabaseLockError,
    DatabaseNotFoundError,
    InvalidCredentialError,
    MattStashError,
    RekeyVerifyError,
    SidecarUpdateError,
)
from ..utils.filelock import FileLock
from ..utils.fileops import copy_private, discard, match_owner, stage_private_file
from ..utils.logging_config import get_logger
from ..utils.validation import (
    validate_credential_title,
    validate_lookup_title,
    validate_notes,
    validate_url,
    validate_username,
)
from .bootstrap import CreatedDatabase, DatabaseBootstrapper
from .entry_manager import EntryManager
from .env_vars import STANDARD_FIELDS, collect_env
from .password_resolver import PasswordResolver, read_password_file

logger = get_logger(__name__)


class _EntrySource:
    """``SecretSource`` over one consistent snapshot of the database (see :mod:`mattstash.core.env_vars`)."""

    def __init__(self, manager: EntryManager) -> None:
        self._manager = manager

    def titles(self, prefix: str) -> List[str]:
        creds = self._manager.list_entries(show_password=False, latest_only=True)
        return [c.credential_name for c in creds if c.credential_name.startswith(prefix)]

    def value(self, title: str, field: str) -> Optional[str]:
        validate_lookup_title(title)
        resolved = self._manager.resolve_entry(title)
        if resolved is None:
            raise CredentialNotFoundError(f"secret not found: {title}")
        entry, _version = resolved
        if field in STANDARD_FIELDS:
            value = getattr(entry, field)
            return value if isinstance(value, str) else None
        return self._manager.custom_property(entry, field)


#: First four bytes of every KeePass (KDBX) file.
_KDBX_SIGNATURE = b"\x03\xd9\xa2\x9a"

#: Every live instance, so a forked child gets fresh mutexes (a lock held by another thread of the parent at the
#: moment of ``fork`` would otherwise stay locked forever in the child).
_INSTANCES: "weakref.WeakSet[MattStash]" = weakref.WeakSet()


def _reset_locks_in_child() -> None:  # pragma: no cover - runs only in a forked child
    for instance in list(_INSTANCES):
        instance._write_mutex = threading.RLock()
        instance._lock = threading.RLock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_locks_in_child)


class MattStash:
    """
    Simple KeePass accessor with:
      - default path of ~/.config/mattstash/mattstash.kdbx (override via ctor)
      - password sources, highest first: explicit ``password`` argument, ``KDBX_PASSWORD``,
        ``KDBX_PASSWORD_FILE``, then the sidecar file next to the DB (``.mattstash.txt``)
      - generic get(title) -> Credential
      - optional env hydration (mapping of keepass 'title:FIELD' -> ENVVAR)

    The constructor never creates a database; use :meth:`create` (or ``mattstash setup``).
    """

    def __init__(self, path: Optional[str] = None, password: Optional[str] = None, *, lock_timeout: float = 30.0):
        # Absolute, so a long-lived instance keeps meaning the same place after a ``chdir``; symlinks are NOT
        # resolved here (they are followed on every access, see ``_real_path``).
        self.path = os.path.abspath(os.path.expanduser(path or config.default_db_path))

        self._password_resolver = PasswordResolver(self.path)
        # Resolve password (lazily failing: a missing password is reported on first use)
        self._password_from_resolver = not password
        self.password = password or self._password_resolver.resolve_password()

        # Lock order (outermost first): _write_mutex (one writer thread) -> _file_lock (other processes) -> _lock.
        # Readers only take _lock, so they wait only while a writer is actually mutating/saving, never while a
        # writer is merely waiting for another process to release the file lock.
        self._lock_timeout = lock_timeout
        self._write_mutex = threading.RLock()
        self._lock = threading.RLock()
        # The lock lives next to the file the path currently resolves to, so two paths to one database (a symlink
        # and its target) share ONE lock. Re-resolved for every write (see ``_exclusive``).
        self._file_lock = FileLock(self._real_path + ".lock", timeout=lock_timeout)
        _INSTANCES.add(self)

        # Initialized on first use
        self._credential_store: Optional[CredentialStore] = None
        self._entry_manager: Optional[EntryManager] = None

        # Initialize helper components for backward compatibility
        self._db_url_builder = DatabaseUrlBuilder(self)
        self._s3_client_builder = S3ClientBuilder(self)

    # ---- creation ---------------------------------------------------------

    @classmethod
    def create(
        cls,
        path: Optional[str] = None,
        password: Optional[str] = None,
        *,
        sidecar: bool = False,
        force: bool = False,
        backup: bool = True,
    ) -> "MattStash":
        """Explicitly create a new database and return a MattStash bound to it.

        See :meth:`DatabaseBootstrapper.create` for the meaning of the options.
        """
        stash, _ = cls.create_with_info(path, password, sidecar=sidecar, force=force, backup=backup)
        return stash

    @classmethod
    def create_with_info(
        cls,
        path: Optional[str] = None,
        password: Optional[str] = None,
        *,
        sidecar: bool = False,
        force: bool = False,
        backup: bool = True,
    ) -> tuple["MattStash", CreatedDatabase]:
        """Like :meth:`create` but also returns the creation details (generated password, backups)."""
        resolved = os.path.expanduser(path or config.default_db_path)
        info = DatabaseBootstrapper(resolved).create(password, sidecar=sidecar, force=force, backup=backup)
        return cls(path=resolved, password=info.password), info

    # ---- internals ----------------------------------------------------------

    @property
    def _real_path(self) -> str:
        """The file ``self.path`` currently resolves to (symlinks followed *now*, not when the object was made).

        A retargeted symlink or a swapped Kubernetes Secret volume (``..data`` -> ``..<timestamp>``) must be
        followed; saves go to the resolved file so a symlinked database stays a symlink.
        """
        return os.path.realpath(self.path)

    def _open(self) -> EntryManager:
        """Open the database if needed. Caller must hold ``self._lock``. Raises on failure."""
        if self._credential_store is None or self._entry_manager is None:
            if not self.password:
                raise DatabaseAccessError(
                    "No database password available: pass one explicitly or set KDBX_PASSWORD, "
                    "KDBX_PASSWORD_FILE or provide a sidecar file"
                )
            for attempt in (1, 2):
                try:
                    store = CredentialStore(self.path, self.password)
                    kp = store.open()  # raises DatabaseNotFoundError / DatabaseAccessError
                    break
                except DatabaseAccessError:
                    # A password read from KDBX_PASSWORD_FILE / the sidecar may have been rotated since this object was
                    # made (a writer queued behind `rotate-password` is the typical case): look once more.
                    refreshed = self._password_resolver.resolve_password() if self._password_from_resolver else None
                    if attempt == 2 or not refreshed or refreshed == self.password:
                        raise
                    self.password = refreshed
                except MattStashError:
                    raise
                except Exception as exc:
                    # Callers only ever need to handle MattStashError.
                    raise DatabaseAccessError(f"Failed to open database: {exc}") from exc
            if kp is None:  # pragma: no cover - defensive
                raise DatabaseAccessError("Unable to open database")
            self._entry_manager = EntryManager(kp, save_callback=self._save)
            self._credential_store = store
        assert self._entry_manager is not None
        return self._entry_manager

    def _not_found_message(self) -> str:
        return f"Database file not found: {self.path}. Create one with 'mattstash setup'."

    def _ensure_initialized(self) -> bool:
        """Ensure the credential store and entry manager are initialized (raises on failure)."""
        with self._lock:
            self._open()
        return True

    def _discard(self) -> None:
        """Drop in-memory state; the next operation re-reads the database from disk."""
        self._credential_store = None
        self._entry_manager = None

    def _save(self) -> None:
        """Save callback for the entry manager: refuses to write if the lock we hold no longer protects anything."""
        self._file_lock.check_current()
        assert self._credential_store is not None
        self._credential_store.save()

    def _reload_locked(self) -> EntryManager:
        assert self._credential_store is not None
        kp = self._credential_store.reload()
        if kp is None:  # pragma: no cover - defensive
            raise DatabaseAccessError("Unable to reload database")
        self._entry_manager = EntryManager(kp, save_callback=self._save)
        return self._entry_manager

    def _fresh(self) -> EntryManager:
        """Entry manager for the current on-disk state. Caller must hold ``self._lock``."""
        store = self._credential_store
        if store is not None and store.real_path != self._real_path:
            self._discard()  # the path now resolves to another file (retargeted symlink, swapped Secret volume)
        manager = self._open()
        assert self._credential_store is not None
        if self._credential_store._current_signature() is None:
            # Deleted or unmounted underneath us: serving the stale in-memory copy would hand out secrets (and
            # report "ready") from a database that is no longer there.
            self._discard()
            raise DatabaseNotFoundError(self._not_found_message())
        if self._credential_store.has_file_changed():
            logger.info("External database modification detected, reloading")
            manager = self._reload_locked()
        return manager

    @contextlib.contextmanager
    def _read(self) -> Iterator[EntryManager]:
        """Context for read operations (thread-safe, sees external changes)."""
        with self._lock:
            yield self._fresh()

    @contextlib.contextmanager
    def _exclusive(self) -> Iterator[None]:
        """One writer at a time across threads AND processes, without blocking readers while waiting.

        ``lock_timeout`` bounds the *whole* wait (other writer threads of this process plus other processes), so
        queued writers do not each wait out the full timeout one after the other.
        """
        deadline = time.monotonic() + self._lock_timeout
        real = self._real_path
        if not os.path.exists(real):
            # Report the real problem (and don't litter a lock file) before locking anything.
            raise DatabaseNotFoundError(self._not_found_message())
        if not self._write_mutex.acquire(timeout=self._lock_timeout):
            raise DatabaseLockError(
                f"Timed out after {self._lock_timeout:.0f}s waiting for another writer in this process"
            )
        try:
            lock_path = real + ".lock"
            if self._file_lock.path != lock_path and not self._file_lock.held:
                self._file_lock = FileLock(lock_path, timeout=self._lock_timeout)  # the path was retargeted
            self._file_lock.acquire(timeout=max(0.0, deadline - time.monotonic()))
            try:
                with self._lock:
                    yield
            finally:
                self._file_lock.release()
        finally:
            self._write_mutex.release()

    @contextlib.contextmanager
    def _write(self) -> Iterator[EntryManager]:
        """Context for read-modify-write operations (thread + process exclusive).

        On any exception the in-memory state is discarded so it cannot diverge from disk.
        """
        with self._exclusive():
            manager = self._fresh()
            try:
                yield manager
            except BaseException:
                self._discard()
                raise

    # ---- Public API -----------------------------------------------------

    def get(self, title: str, show_password: bool = False, version: Optional[int] = None) -> Optional[CredentialResult]:
        """
        Fetch a KeePass entry by its Title (optionally versioned) and return a Credential payload.

        Returns None if there is no such entry.

        Raises:
            DatabaseNotFoundError, DatabaseAccessError: the database itself cannot be opened.
        """
        validate_lookup_title(title)
        with self._read() as manager:
            return manager.get_entry(title, show_password, version)

    def list(self, show_password: bool = False, latest_only: bool = False) -> List[Credential]:
        """
        Return a list of Credential objects for all entries in the KeePass database.

        With ``latest_only`` versioned entries are collapsed to their base name (latest version).
        """
        with self._read() as manager:
            return manager.list_entries(show_password, latest_only=latest_only)

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
        # Validate before taking any lock or touching state.
        validate_credential_title(title)
        validate_username(username)
        validate_url(url)
        validate_notes(notes)

        with self._write() as manager:
            return manager.put_entry(
                title,
                value=value,
                username=username,
                password=password,
                url=url,
                notes=notes,
                tags=tags,
                version=version,
                autoincrement=autoincrement,
            )

    def list_versions(self, title: str) -> List[str]:
        """
        List all versions (zero-padded strings) for a given title, sorted ascending.
        """
        validate_lookup_title(title)
        with self._read() as manager:
            return manager.list_versions(title)

    def delete(self, title: str, version: Optional[int] = None) -> bool:
        """
        Delete an entry by title: the unversioned entry and all its versions
        (or just one version if ``version`` is given). Returns True if anything was deleted.
        """
        validate_lookup_title(title)
        with self._write() as manager:
            return manager.delete_entry(title, version)

    def prune(self, title: str, keep: int) -> List[str]:
        """Delete all but the newest ``keep`` versions of ``title``; returns the deleted versions."""
        validate_lookup_title(title)
        with self._write() as manager:
            return manager.prune_versions(title, keep)

    # ---- operations -------------------------------------------------------------

    def _backup_target(self, dest: Optional[str]) -> str:
        """Where a backup goes: ``dest`` (a file, or a directory to put the default name in) or next to the DB.

        Default names carry a UTC timestamp with microseconds and get a counter if they still collide, so two
        backups in the same second (``backup`` followed by ``rotate-password``) never fail for want of a name.
        """
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        base = os.path.basename(self.path)

        def default_in(directory: str) -> str:
            candidate = os.path.join(directory, f"{base}.bak-{stamp}")
            for attempt in range(1, 1000):
                if not os.path.lexists(candidate):
                    break
                candidate = os.path.join(directory, f"{base}.bak-{stamp}-{attempt}")
            return candidate

        if dest is None:
            return default_in(os.path.dirname(self.path))
        target = os.path.expanduser(dest)
        if os.path.isdir(target):
            return default_in(target)
        if target.endswith(("/", os.sep)):
            raise MattStashError(f"Backup directory does not exist: {target}")
        return target

    def _copy_locked(self, dest: Optional[str], force: bool) -> str:
        """Copy the database file to ``dest``. The caller holds the thread and file locks."""
        target = self._backup_target(dest)
        directory = os.path.dirname(os.path.abspath(target))
        if not os.path.isdir(directory):
            raise MattStashError(f"Backup directory does not exist: {directory}")
        real = self._real_path
        protected = {self.path, real, real + ".lock", PasswordResolver(self.path).sidecar_path}
        if os.path.realpath(target) in {os.path.realpath(p) for p in protected}:
            raise MattStashError("Refusing to write the backup over the database, its lock or its sidecar file")
        # Refuse to preserve garbage (a truncated or emptied file) -- and, with force, to overwrite the last good
        # backup with it. Every KDBX file starts with this signature; checking it needs no password.
        try:
            with open(real, "rb") as source:
                signature = source.read(4)
        except FileNotFoundError:
            raise DatabaseNotFoundError(self._not_found_message()) from None
        except OSError as exc:
            raise DatabaseAccessError(f"Cannot read the database file: {exc.strerror or exc}") from exc
        if signature != _KDBX_SIGNATURE:
            raise DatabaseAccessError(
                f"{self.path} is not a valid KeePass database (empty or truncated?); refusing to back it up"
            )
        try:
            copy_private(real, target, overwrite=force)
        except FileExistsError:
            raise DatabaseExistsError(
                f"Refusing to overwrite existing file: {target} (use force to replace it)"
            ) from None
        except OSError as exc:
            raise MattStashError(f"Backup to {target} failed: {exc.strerror or exc}") from exc
        logger.info("Database backed up to %s", target)
        return target

    def backup(self, dest: Optional[str] = None, *, force: bool = False) -> str:
        """Write a consistent, private copy of the database file and return its path.

        The copy is taken while holding the write lock, so it cannot interleave with a writer. It is
        written to a temp file (mode 0600) and renamed into place, so ``dest`` is never left partial.

        Args:
            dest: target file, or an existing directory (the default file name is used inside it).
                Default: ``<db>.bak-<UTC timestamp>`` next to the database.
            force: replace ``dest`` if it already exists (otherwise ``DatabaseExistsError``).

        The backup is the encrypted file as it is: it needs (and contains) no password, and the sidecar
        file is not copied. It can be opened with the master password that was current when it was made.

        Raises:
            DatabaseNotFoundError: there is no database file.
            DatabaseLockError: another process held the write lock for too long.
            DatabaseExistsError: ``dest`` exists and ``force`` is False.
        """
        with self._exclusive():
            return self._copy_locked(dest, force)

    def rotate_password(self, new_password: str, *, backup: bool = False) -> Optional[str]:
        """Change the master password of the database.

        Under the write lock this verifies that the current password opens the database, optionally copies
        the file first (``backup=True``; the copy keeps the *old* password and its path is returned), re-keys
        and saves the database, and updates the sidecar password file next to the database -- but only if that
        file holds the password this database was just opened with (one ``.mattstash.txt`` per directory can
        belong to a different database, whose only password record must not be overwritten). The sidecar is
        replaced atomically (mode 0600, symlinks followed) right after the re-key; the database is then re-read
        from disk with the new password to prove it works.

        ``self.password`` is updated. Other processes that hold the old password (a server, ``KDBX_PASSWORD``
        in an environment) can no longer open the database until they are given the new one.

        Raises:
            DatabaseAccessError: the current password is wrong/missing (nothing is changed).
            InvalidCredentialError: the new password is empty, or has leading/trailing whitespace while a
                sidecar will be updated (password files are read with surrounding whitespace stripped).
            DatabaseLockError: another process held the write lock for too long (nothing is changed).
            RotationIncompleteError: the database *was* re-keyed but something after that failed:
                ``SidecarUpdateError`` (the sidecar could not be replaced; the new password is kept in
                ``staged_path``) or ``RekeyVerifyError`` (re-reading failed). The new password is in effect and the
                caller must show it to the user. ``backup_path`` on any exception names the pre-rotation backup.
        """
        if not isinstance(new_password, str) or not new_password:
            raise InvalidCredentialError("The new password cannot be empty")
        backup_path: Optional[str] = None
        try:
            with self._write():  # opens (verifies the current password) under the thread and file locks
                assert self._credential_store is not None
                store = self._credential_store
                sidecar_target = self._managed_sidecar(self.password)
                if sidecar_target is not None and new_password != new_password.strip():
                    raise InvalidCredentialError(
                        "The new password has leading or trailing whitespace, which the sidecar password file "
                        "cannot hold"
                    )
                if backup:
                    backup_path = self._copy_locked(None, False)
                staged = stage_private_file(sidecar_target, new_password.encode()) if sidecar_target else None
                if staged is not None:
                    with contextlib.suppress(OSError):
                        match_owner(os.stat(sidecar_target), staged)  # type: ignore[arg-type]
                before = store._current_signature()
                try:
                    store.change_password(new_password)
                except BaseException:
                    if store._current_signature() != before:
                        # The file was replaced before the interruption: the database really has the new password,
                        # and the staged file is the only other record of it. Roll forward, never discard.
                        self.password = new_password
                        if staged is not None:
                            with contextlib.suppress(OSError):
                                os.replace(staged, sidecar_target)  # type: ignore[arg-type]
                    else:
                        discard(staged)
                    raise
                self.password = new_password
                # From here on the database only opens with the new password and the sidecar is the only other
                # record of it: publish it NOW, before the (seconds-long) verification, and never delete the staged
                # file again -- if the swap fails it is the operator's only copy.
                if staged is not None:
                    try:
                        os.replace(staged, sidecar_target)  # type: ignore[arg-type]  # atomic; consumes the file
                    except OSError as exc:
                        error = SidecarUpdateError(
                            f"The database now uses the new password, but the sidecar file {sidecar_target} "
                            f"could not be updated: {exc.strerror or exc}. The new password is saved in {staged}"
                        )
                        error.staged_path = staged
                        raise error from exc
                try:
                    self._reload_locked()  # prove the new password opens what was written
                except Exception as exc:
                    raise RekeyVerifyError(
                        "The database was re-keyed and saved, but re-reading it with the new password failed "
                        f"({exc}); the database and the sidecar both use the NEW password: check with `mattstash list`"
                    ) from exc
        except BaseException as exc:
            if backup_path is not None:
                with contextlib.suppress(Exception):
                    exc.backup_path = backup_path  # type: ignore[attr-defined]
            raise
        logger.info("Master password rotated")
        return backup_path

    def _managed_sidecar(self, current_password: Optional[str]) -> Optional[str]:
        """The sidecar file to update on rotation, or ``None`` if there is none or it is not this database's.

        One ``.mattstash.txt`` serves a whole directory. It belongs to this database only if it holds the password
        the database was opened with; otherwise it records another database's password (or a stale one) and
        replacing it would destroy that record.
        """
        sidecar = PasswordResolver(self.path).sidecar_path
        if not os.path.exists(sidecar):
            return None
        target = os.path.realpath(sidecar)  # a symlinked sidecar is updated through the link
        try:
            held = read_password_file(target)
        except (OSError, UnicodeDecodeError):
            held = None
        if held != current_password:
            logger.warning(
                "The sidecar %s does not hold this database's password (another database in the same directory, or "
                "a stale file): it is left unchanged",
                sidecar,
            )
            return None
        return target

    def reload(self) -> bool:
        """
        Reload the KeePass database from disk.
        Useful when the file has been modified externally (e.g., by the CLI).

        Returns:
            True if reload was successful, False otherwise.
        """
        with self._lock:
            if self._credential_store is None:
                # Not yet initialized; just open it
                try:
                    self._open()
                    return True
                except MattStashError as e:
                    logger.error(f"Failed to open database: {e}")
                    return False

            try:
                self._reload_locked()
                logger.info("Database reloaded successfully")
                return True
            except Exception as e:
                logger.error(f"Failed to reload database: {e}")
                self._discard()  # never keep a store that lost its database: the next operation re-opens it
                return False

    def reload_if_changed(self) -> bool:
        """
        Check if the KDBX file has been modified externally and reload if so.

        Returns:
            True if a reload was performed, False if no change was detected.
        """
        with self._lock:
            if self._credential_store is None:
                return False

            if self._credential_store.has_file_changed():
                logger.info("External database modification detected, reloading")
                return self.reload()
            return False

    def hydrate_env(self, mapping: Dict[str, str]) -> None:
        """
        For each mapping 'Title:FIELD' -> ENVVAR, if ENVVAR is unset, read from KeePass.
        The latest version of the entry is used. FIELD supports:
          - AWS_ACCESS_KEY_ID  -> entry.username
          - AWS_SECRET_ACCESS_KEY -> entry.password
          - otherwise -> custom property with that FIELD name
        """
        with self._read() as manager:
            for src, envname in mapping.items():
                if os.environ.get(envname):
                    continue
                if ":" not in src:
                    logger.warning("Invalid mapping key %r: expected 'Title:FIELD' format", src)
                    continue
                base_title, field = src.split(":", 1)
                resolved = manager.resolve_entry(base_title)
                if resolved is None:
                    continue
                entry, _version = resolved
                if field == "AWS_ACCESS_KEY_ID":
                    value = entry.username
                elif field == "AWS_SECRET_ACCESS_KEY":
                    value = entry.password
                else:
                    value = manager.custom_property(entry, field)
                if value:
                    os.environ[envname] = value

    def resolve_env(
        self,
        prefix: Optional[str] = None,
        mappings: Optional[Mapping[str, str] | Iterable[str]] = None,
        *,
        strip_prefix: bool = True,
        upper: bool = False,
        allow_reserved: bool = False,
    ) -> Dict[str, str]:
        """Environment variables for a set of secrets (the engine behind ``mattstash env`` / ``exec``).

        Args:
            prefix: every secret whose base title starts with this becomes a variable. The name is the
                title without the prefix (kept with ``strip_prefix=False``), with characters outside
                ``[A-Za-z0-9_]`` replaced by ``_`` and upper-cased if ``upper``. ``""`` selects everything.
            mappings: explicit ``{ENVVAR: "TITLE[:FIELD]"}`` (or an iterable of ``"ENVVAR=TITLE[:FIELD]"``
                strings). ``FIELD`` is ``password`` (default), ``username``, ``url``, ``notes`` or the name
                of a custom property. A title containing ``:`` needs an explicit field.
            strip_prefix: remove ``prefix`` from derived names (default True).
            upper: upper-case derived names.
            allow_reserved: allow names derived from ``prefix`` to be loader/shell control variables such as
                ``LD_PRELOAD`` or ``PATH`` (refused by default; explicit ``mappings`` are never restricted).

        The latest version of each secret is used and everything is read from one consistent snapshot.
        Values are returned in memory only; nothing is logged or written.

        Raises:
            ValueError: nothing selected, an invalid name/mapping, a NUL byte in a value or a name collision.
            CredentialNotFoundError: a mapped secret (or field value) is missing, or ``prefix`` matches nothing.
            DatabaseNotFoundError, DatabaseAccessError: the database itself cannot be opened.
        """
        with self._read() as manager:
            return collect_env(
                _EntrySource(manager),
                prefix=prefix,
                mappings=mappings,
                strip_prefix=strip_prefix,
                upper=upper,
                allow_reserved=allow_reserved,
            )

    def get_entry_with_properties(
        self, title: str, custom_property_names: tuple[str, ...] = ()
    ) -> Optional[tuple[CredentialResult, Dict[str, Optional[str]]]]:
        """Return the (unmasked) credential for ``title`` plus the requested custom properties.

        Used by the URL/S3 builders so the whole lookup happens under one consistent snapshot.
        """
        validate_lookup_title(title)
        with self._read() as manager:
            found = manager.get_entry_with_custom_properties(title)
            if found is None:
                return None
            cred, entry = found
            props = {name: manager.custom_property(entry, name) for name in custom_property_names}
            return cred, props

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
