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
from collections.abc import Iterable, Iterator, Mapping
from typing import Any, Dict, List, Optional, Union

from ..builders.db_url import DatabaseUrlBuilder
from ..builders.s3_client import S3ClientBuilder
from ..credential_store import CredentialStore
from ..models.config import config
from ..models.credential import Credential, CredentialResult
from ..utils.exceptions import (
    CredentialNotFoundError,
    DatabaseAccessError,
    DatabaseExistsError,
    DatabaseNotFoundError,
    InvalidCredentialError,
    MattStashError,
    SidecarUpdateError,
)
from ..utils.filelock import FileLock
from ..utils.fileops import copy_private, discard, stage_private_file
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
from .password_resolver import PasswordResolver

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
        self.path = os.path.expanduser(path or config.default_db_path)

        self._password_resolver = PasswordResolver(self.path)
        # Resolve password (lazily failing: a missing password is reported on first use)
        self.password = password or self._password_resolver.resolve_password()

        self._lock = threading.RLock()
        self._file_lock = FileLock(self.path + ".lock", timeout=lock_timeout)

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

    def _open(self) -> EntryManager:
        """Open the database if needed. Caller must hold ``self._lock``. Raises on failure."""
        if self._credential_store is None or self._entry_manager is None:
            if not self.password:
                raise DatabaseAccessError(
                    "No database password available: pass one explicitly or set KDBX_PASSWORD, "
                    "KDBX_PASSWORD_FILE or provide a sidecar file"
                )
            try:
                store = CredentialStore(self.path, self.password)
                kp = store.open()  # raises DatabaseNotFoundError / DatabaseAccessError
            except MattStashError:
                raise
            except Exception as exc:
                # Callers only ever need to handle MattStashError.
                raise DatabaseAccessError(f"Failed to open database: {exc}") from exc
            if kp is None:  # pragma: no cover - defensive
                raise DatabaseAccessError("Unable to open database")
            self._entry_manager = EntryManager(kp, save_callback=store.save)
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

    def _reload_locked(self) -> EntryManager:
        assert self._credential_store is not None
        kp = self._credential_store.reload()
        if kp is None:  # pragma: no cover - defensive
            raise DatabaseAccessError("Unable to reload database")
        self._entry_manager = EntryManager(kp, save_callback=self._credential_store.save)
        return self._entry_manager

    def _fresh(self) -> EntryManager:
        """Entry manager for the current on-disk state. Caller must hold ``self._lock``."""
        manager = self._open()
        assert self._credential_store is not None
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
    def _write(self) -> Iterator[EntryManager]:
        """Context for read-modify-write operations (thread + process exclusive).

        On any exception the in-memory state is discarded so it cannot diverge from disk.
        """
        if not os.path.exists(self.path):
            # Report the real problem (and don't litter a lock file) before locking anything.
            raise DatabaseNotFoundError(self._not_found_message())
        with self._lock, self._file_lock:
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
        """Where a backup goes: ``dest`` (a file, or a directory to put the default name in) or next to the DB."""
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        default_name = f"{os.path.basename(self.path)}.bak-{stamp}"
        if dest is None:
            return os.path.join(os.path.dirname(self.path), default_name)
        target = os.path.expanduser(dest)
        if os.path.isdir(target):
            return os.path.join(target, default_name)
        return target

    def _copy_locked(self, dest: Optional[str], force: bool) -> str:
        """Copy the database file to ``dest``. The caller holds the thread and file locks."""
        target = self._backup_target(dest)
        directory = os.path.dirname(os.path.abspath(target))
        if not os.path.isdir(directory):
            raise MattStashError(f"Backup directory does not exist: {directory}")
        protected = {self.path, self.path + ".lock", PasswordResolver(self.path).sidecar_path}
        if os.path.realpath(target) in {os.path.realpath(p) for p in protected}:
            raise MattStashError("Refusing to write the backup over the database, its lock or its sidecar file")
        try:
            copy_private(self.path, target, overwrite=force)
        except FileExistsError:
            raise DatabaseExistsError(
                f"Refusing to overwrite existing file: {target} (use force to replace it)"
            ) from None
        except FileNotFoundError:
            raise DatabaseNotFoundError(self._not_found_message()) from None
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
        if not os.path.exists(self.path):
            raise DatabaseNotFoundError(self._not_found_message())
        with self._lock, self._file_lock:
            return self._copy_locked(dest, force)

    def rotate_password(self, new_password: str, *, backup: bool = False) -> Optional[str]:
        """Change the master password of the database.

        Under the write lock this verifies that the current password opens the database, optionally copies
        the file first (``backup=True``; the copy keeps the *old* password and its path is returned), re-keys
        and saves the database, re-opens it from disk with the new password to prove it works, and updates
        the sidecar password file next to the database if there is one (atomically, mode 0600). The
        sidecar temp file is prepared before the database is touched, so a failure cannot leave the sidecar
        changed while the database is not.

        ``self.password`` is updated. Other processes that hold the old password (a server, ``KDBX_PASSWORD``
        in an environment) can no longer open the database until they are given the new one.

        Raises:
            DatabaseAccessError: the current password is wrong/missing (nothing is changed).
            InvalidCredentialError: the new password is empty, or has leading/trailing whitespace while a
                sidecar exists (password files are read with surrounding whitespace stripped).
            DatabaseLockError: another process held the write lock for too long (nothing is changed).
            SidecarUpdateError: the database *was* re-keyed but the sidecar could not be replaced.
        """
        if not isinstance(new_password, str) or not new_password:
            raise InvalidCredentialError("The new password cannot be empty")
        sidecar = PasswordResolver(self.path).sidecar_path
        has_sidecar = os.path.exists(sidecar)
        if has_sidecar and new_password != new_password.strip():
            raise InvalidCredentialError(
                "The new password has leading or trailing whitespace, which the sidecar password file cannot hold"
            )

        backup_path: Optional[str] = None
        with self._write():  # opens (verifies the current password) under the thread and file locks
            assert self._credential_store is not None
            store = self._credential_store
            if backup:
                backup_path = self._copy_locked(None, False)
            staged = stage_private_file(sidecar, new_password.encode()) if has_sidecar else None
            try:
                store.change_password(new_password)
                self.password = new_password
                try:
                    self._reload_locked()  # prove the new password opens what was written
                except MattStashError as exc:
                    raise DatabaseAccessError(
                        "The database was re-keyed but could not be re-opened with the new password"
                        + (f"; restore it from the backup {backup_path}" if backup_path else "")
                    ) from exc
                if staged is not None:
                    try:
                        os.replace(staged, sidecar)  # atomic; consumes the staged file
                    except OSError as exc:
                        raise SidecarUpdateError(
                            f"The database now uses the new password, but the sidecar file {sidecar} "
                            f"could not be updated: {exc.strerror or exc}"
                        ) from exc
            finally:
                discard(staged)  # no-op once the staged file has replaced the sidecar
        logger.info("Master password rotated")
        return backup_path

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
        mappings: Optional[Union[Mapping[str, str], Iterable[str]]] = None,
        *,
        strip_prefix: bool = True,
        upper: bool = False,
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

        The latest version of each secret is used and everything is read from one consistent snapshot.
        Values are returned in memory only; nothing is logged or written.

        Raises:
            ValueError: nothing selected, an invalid name/mapping, a NUL byte in a value or a name collision.
            CredentialNotFoundError: a mapped secret (or field value) is missing, or ``prefix`` matches nothing.
            DatabaseNotFoundError, DatabaseAccessError: the database itself cannot be opened.
        """
        with self._read() as manager:
            return collect_env(
                _EntrySource(manager), prefix=prefix, mappings=mappings, strip_prefix=strip_prefix, upper=upper
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
