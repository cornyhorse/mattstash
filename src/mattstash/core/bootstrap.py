"""
mattstash.core.bootstrap
------------------------
Explicit database creation (``mattstash setup``).

Nothing in MattStash creates a database implicitly: opening a missing database is an
error, so a mistyped path or an unmounted volume can never silently produce a fresh,
empty database. Creation is only reachable through :meth:`DatabaseBootstrapper.create`
(``MattStash.create`` / ``mattstash setup``).

Safety properties of :meth:`~DatabaseBootstrapper.create`:

* it holds the database's cross-process lock (``<db>.lock``, the same one writers use) for the whole
  operation, so it cannot interleave with a writer or with another ``create``;
* temporary files have unique names, so concurrent creators never share a temp file;
* without ``force`` the final step is an atomic create-if-absent (``os.link``), so when several processes race
  exactly one wins and the others get ``DatabaseExistsError``;
* backups are never overwritten (timestamps have microsecond resolution and collisions get a counter);
* everything fallible is prepared before the first destructive step, and a failure while swapping restores the
  previous sidecar, so the old database is never left without its password.
"""

import contextlib
import errno
import os
import secrets
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Optional

from ..models.config import config
from ..utils.exceptions import DatabaseExistsError, MattStashError
from ..utils.filelock import FileLock
from ..utils.fileops import match_owner, staging_name
from ..utils.logging_config import get_logger
from .password_resolver import PasswordResolver

logger = get_logger(__name__)

try:
    from pykeepass import create_database as _kp_create_database
except Exception:  # pragma: no cover
    _kp_create_database = None


@dataclass
class CreatedDatabase:
    """Result of :meth:`DatabaseBootstrapper.create`."""

    db_path: str
    password: str
    generated: bool
    sidecar_path: Optional[str] = None
    backups: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _makedirs_private(path: str) -> None:
    """Create ``path`` and any missing parents as 0700 whatever the umask (``os.makedirs`` applies the mode to the
    leaf only, and a restrictive umask can leave an intermediate directory unusable)."""
    missing = []
    probe = os.path.abspath(path)
    while probe and not os.path.isdir(probe):
        missing.append(probe)
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    for directory in reversed(missing):
        os.makedirs(directory, mode=0o700, exist_ok=True)
        with contextlib.suppress(OSError):  # pragma: no cover - non-POSIX
            os.chmod(directory, 0o700)


def _write_private(path: str, data: bytes) -> None:
    """Write ``data`` to a brand-new file that is 0600 from the moment it exists."""
    with contextlib.suppress(FileNotFoundError):
        os.remove(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with contextlib.suppress(OSError, AttributeError):
        os.fchmod(fd, 0o600)  # the umask must not make it unwritable (or unreadable) for its owner
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _link_or_replace(src: str, dst: str, *, replace: bool) -> None:
    """Move ``src`` to ``dst``.

    ``replace=False`` is create-if-absent: it raises ``FileExistsError`` if ``dst`` exists, atomically (hard link),
    so concurrent creators cannot both succeed. ``replace=True`` overwrites.
    """
    if replace:
        os.replace(src, dst)
        return
    try:
        os.link(src, dst)
    except FileExistsError:
        raise
    except OSError:
        # filesystems without hard links: fall back to a check + rename (we hold the database lock)
        if os.path.exists(dst):
            raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), dst) from None
        os.replace(src, dst)
        return
    os.remove(src)


class DatabaseBootstrapper:
    """Creates a new KeePass database (and optionally the sidecar password file)."""

    def __init__(self, db_path: str, sidecar_basename: Optional[str] = None):
        #: The path as given (the sidecar lives next to it).
        self.db_path = db_path
        self.sidecar_basename = sidecar_basename or config.sidecar_basename

    @property
    def real_db_path(self) -> str:
        """The file the database path resolves to *now*: what writers lock, replace and back up.

        ``setup --force`` on a symlinked path must replace the target (keeping the link) under the same lock the
        writers use, not replace the link itself.
        """
        return os.path.realpath(self.db_path)

    @property
    def db_dir(self) -> str:
        return os.path.dirname(self.db_path) or "."

    @property
    def sidecar_path(self) -> str:
        return os.path.join(self.db_dir, self.sidecar_basename)

    def existing_files(self) -> list[str]:
        """Paths that creating a database here would replace."""
        # lexists for the sidecar: a dangling symlink there still blocks the swap
        return [p for p in (self.real_db_path, self.sidecar_path) if os.path.lexists(p)]

    @staticmethod
    def _backup(path: str) -> str:
        """Copy ``path`` to a fresh ``<path>.bak-<UTC microseconds>`` file (0600); never overwrites a backup."""
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        for attempt in range(1000):
            dest = f"{path}.bak-{stamp}" + (f"-{attempt}" if attempt else "")
            try:
                fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                continue
            with contextlib.suppress(OSError, AttributeError):
                os.fchmod(fd, 0o600)  # the umask must not leave the backup unwritable for its owner
            os.close(fd)
            try:
                shutil.copyfile(path, dest)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.remove(dest)  # a truncated ".bak" next to the real file would look like a good backup
                raise
            return dest
        raise MattStashError(f"Could not find a free backup name for {path}")  # pragma: no cover

    def create(
        self,
        password: Optional[str] = None,
        *,
        sidecar: bool = False,
        force: bool = False,
        backup: bool = True,
        lock_timeout: float = 30.0,
    ) -> CreatedDatabase:
        """Create a new database.

        Args:
            password: Master password. If omitted, ``KDBX_PASSWORD`` /
                ``KDBX_PASSWORD_FILE`` are used (never the sidecar); if those are unset a
                strong random password is generated (``result.generated`` is True).
            sidecar: Also write the password to ``<db_dir>/.mattstash.txt`` (0600).
            force: Replace existing files instead of refusing.
            backup: With ``force``, copy existing files to ``<name>.bak-<UTC timestamp>`` first.
            lock_timeout: Seconds to wait for a writer (or another ``create``) holding the database lock.

        Raises:
            DatabaseExistsError: files exist and ``force`` is False.
            DatabaseLockError: the database lock could not be acquired in time.
            MattStashError: creation failed; the previous files are left untouched.
        """
        if _kp_create_database is None:
            raise MattStashError("pykeepass.create_database is not available in this version")

        generated = False
        if not password:
            password = PasswordResolver(self.db_path, self.sidecar_basename).resolve_from_environment()
        if not password:
            password = secrets.token_urlsafe(32)
            generated = True
        padded = password != password.strip()
        if padded and sidecar:
            # Password files are read with surrounding whitespace stripped, so the sidecar could never open
            # the database it was written for.
            raise MattStashError(
                "The master password has leading or trailing whitespace, which a sidecar password file cannot hold"
            )

        # Directory: restrictive perms only if we are the ones creating it.
        real_dir = os.path.dirname(self.real_db_path) or "."
        for directory in dict.fromkeys((self.db_dir, real_dir)):
            if not os.path.isdir(directory):
                try:
                    _makedirs_private(directory)
                except OSError as exc:
                    raise MattStashError(f"Cannot create the directory {directory}: {exc.strerror or exc}") from exc

        # Writers and other creators serialise on the same lock file, so a writer cannot finish a save
        # (and rename an old-password copy over the new database) in the middle of a replacement.
        with FileLock(self.real_db_path + ".lock", timeout=lock_timeout):
            return self._create_locked(password, generated, sidecar=sidecar, force=force, backup=backup, padded=padded)

    def _create_locked(
        self, password: str, generated: bool, *, sidecar: bool, force: bool, backup: bool, padded: bool = False
    ) -> CreatedDatabase:
        assert _kp_create_database is not None
        existing = self.existing_files()
        if existing and not force:
            raise DatabaseExistsError("Refusing to overwrite existing files: " + ", ".join(existing))

        # --- 1) prepare everything that can fail, touching nothing that exists -------------------
        backups: list[str] = []
        new_sidecar = None
        old_sidecar: Optional[bytes] = None  # kept in memory so a failed swap can restore it even without backups
        token = secrets.token_hex(6)  # unique per call: concurrent creators never share a temp file
        real_db = self.real_db_path
        real_dir = os.path.dirname(real_db) or "."
        new_db = staging_name(real_dir, os.path.basename(real_db), token)
        temp_sidecar = staging_name(self.db_dir, self.sidecar_basename, token)
        leftovers = [new_db, os.path.splitext(new_db)[0] + ".tmp", temp_sidecar]
        try:
            if os.path.exists(self.sidecar_path):
                with open(self.sidecar_path, "rb") as f:
                    old_sidecar = f.read()
            if existing and backup:
                for path in existing:
                    backups.append(self._backup(path))

            # pykeepass writes "<stem>.tmp" then moves it over the target; pre-create that temp file 0600
            # (it is opened with truncation, which keeps the mode) so the database is never visible with
            # default-umask permissions.
            _write_private(os.path.splitext(new_db)[0] + ".tmp", b"")
            _kp_create_database(new_db, password=password)
            with contextlib.suppress(OSError):  # best effort: not every filesystem supports chmod
                os.chmod(new_db, 0o600)
            if sidecar:
                _write_private(temp_sidecar, password.encode())
                new_sidecar = temp_sidecar
        except Exception as exc:
            self._cleanup(leftovers)
            logger.error(f"Failed to create KeePass DB: {exc}")
            raise MattStashError(f"Failed to create database: {exc}{self._backup_note(backups)}") from exc

        # --- 2) swap in. Old files were backed up above; the database goes LAST ---------------------
        sidecar_swapped = False
        warnings: list[str] = []
        if padded:
            warnings.append(
                "the master password has leading or trailing whitespace: it cannot be supplied through "
                "KDBX_PASSWORD_FILE or a sidecar file (those are read with whitespace stripped)"
            )
        # Replacing files as root must not turn the service user's database into a root-owned one it cannot read.
        for old, new in ((real_db, new_db), (self.sidecar_path, new_sidecar)):
            if new is not None and os.path.exists(old):
                with contextlib.suppress(OSError):
                    match_owner(os.stat(old), new)
        try:
            if new_sidecar is not None:
                _link_or_replace(new_sidecar, self.sidecar_path, replace=force)
                sidecar_swapped = True
            _link_or_replace(new_db, real_db, replace=force)
        except FileExistsError as exc:
            self._restore_sidecar(sidecar_swapped, old_sidecar)
            self._cleanup(leftovers)
            # os.link(src, dst) reports the *source* in .filename and the destination in .filename2
            raise DatabaseExistsError(
                f"Refusing to overwrite {exc.filename2 or exc.filename or self.db_path}"
            ) from None
        except OSError as exc:
            self._restore_sidecar(sidecar_swapped, old_sidecar)
            self._cleanup(leftovers)
            raise MattStashError(
                f"Failed to install the new database: {exc.strerror or exc}{self._backup_note(backups)}"
            ) from exc
        finally:
            self._cleanup(leftovers)

        if new_sidecar is None and os.path.exists(self.sidecar_path):
            # A stale sidecar holds the OLD password (and would mislead the resolver). The new database is
            # already in place, so a failure here is reported, not fatal.
            try:
                os.remove(self.sidecar_path)
            except OSError as exc:
                warnings.append(f"could not remove the old sidecar {self.sidecar_path}: {exc.strerror or exc}")

        logger.info(f"Created new KeePass DB at {self.db_path}")
        return CreatedDatabase(
            db_path=self.db_path,
            password=password,
            generated=generated,
            sidecar_path=self.sidecar_path if sidecar else None,
            backups=backups,
            warnings=warnings,
        )

    @staticmethod
    def _backup_note(backups: list[str]) -> str:
        """Tell the operator where the safety copies are (the old sidecar copy holds the old password in plain text)."""
        if not backups:
            return ""
        return "; the previous files were backed up first and are kept: " + ", ".join(backups)

    @staticmethod
    def _cleanup(paths: list[str]) -> None:
        for leftover in paths:
            with contextlib.suppress(OSError):
                os.remove(leftover)

    def _restore_sidecar(self, swapped: bool, old_content: Optional[bytes]) -> None:
        """Undo a sidecar swap after the database swap failed, so the (unchanged) old database keeps its password."""
        if not swapped:
            return
        with contextlib.suppress(OSError):
            if old_content is not None:
                restore = f"{self.sidecar_path}.{secrets.token_hex(6)}.restore"
                _write_private(restore, old_content)
                os.replace(restore, self.sidecar_path)
            else:
                os.remove(self.sidecar_path)
