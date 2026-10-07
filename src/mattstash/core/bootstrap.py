"""
mattstash.core.bootstrap
------------------------
Explicit database creation (``mattstash setup``).

Nothing in MattStash creates a database implicitly: opening a missing database is an
error, so a mistyped path or an unmounted volume can never silently produce a fresh,
empty database. Creation is only reachable through :meth:`DatabaseBootstrapper.create`
(``MattStash.create`` / ``mattstash setup``).
"""

import contextlib
import os
import secrets
import shutil
import time
from dataclasses import dataclass, field
from typing import Optional

from ..models.config import config
from ..utils.exceptions import DatabaseExistsError, MattStashError
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


def _write_private(path: str, data: bytes) -> None:
    """Write ``data`` to a brand-new file that is 0600 from the moment it exists."""
    with contextlib.suppress(FileNotFoundError):
        os.remove(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


class DatabaseBootstrapper:
    """Creates a new KeePass database (and optionally the sidecar password file)."""

    def __init__(self, db_path: str, sidecar_basename: Optional[str] = None):
        self.db_path = db_path
        self.sidecar_basename = sidecar_basename or config.sidecar_basename

    @property
    def db_dir(self) -> str:
        return os.path.dirname(self.db_path) or "."

    @property
    def sidecar_path(self) -> str:
        return os.path.join(self.db_dir, self.sidecar_basename)

    def existing_files(self) -> list[str]:
        """Paths that creating a database here would replace."""
        return [p for p in (self.db_path, self.sidecar_path) if os.path.exists(p)]

    def create(
        self,
        password: Optional[str] = None,
        *,
        sidecar: bool = False,
        force: bool = False,
        backup: bool = True,
    ) -> CreatedDatabase:
        """Create a new database.

        Args:
            password: Master password. If omitted, ``KDBX_PASSWORD`` /
                ``KDBX_PASSWORD_FILE`` are used (never the sidecar); if those are unset a
                strong random password is generated (``result.generated`` is True).
            sidecar: Also write the password to ``<db_dir>/.mattstash.txt`` (0600).
            force: Replace existing files instead of refusing.
            backup: With ``force``, copy existing files to ``<name>.bak-<UTC timestamp>`` first.

        Raises:
            DatabaseExistsError: files exist and ``force`` is False.
            MattStashError: creation failed; the previous files are left untouched.
        """
        existing = self.existing_files()
        if existing and not force:
            raise DatabaseExistsError("Refusing to overwrite existing files: " + ", ".join(existing))
        if _kp_create_database is None:
            raise MattStashError("pykeepass.create_database is not available in this version")

        generated = False
        if not password:
            password = PasswordResolver(self.db_path, self.sidecar_basename).resolve_from_environment()
        if not password:
            password = secrets.token_urlsafe(32)
            generated = True

        # Directory: restrictive perms only if we are the ones creating it.
        if not os.path.isdir(self.db_dir):
            os.makedirs(self.db_dir, mode=0o700, exist_ok=True)
            with contextlib.suppress(OSError):  # pragma: no cover - non-POSIX
                os.chmod(self.db_dir, 0o700)

        backups: list[str] = []
        if existing and backup:
            stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            for path in existing:
                dest = f"{path}.bak-{stamp}"
                _write_private(dest, b"")
                shutil.copyfile(path, dest)
                backups.append(dest)

        new_db = f"{self.db_path}.new"
        new_sidecar = f"{self.sidecar_path}.new"
        try:
            # pykeepass writes "<name>.tmp" then moves it over the target; pre-create that temp
            # file 0600 (it is opened with truncation, which keeps the mode) so the database is
            # never visible with default-umask permissions.
            _write_private(os.path.splitext(new_db)[0] + ".tmp", b"")
            _kp_create_database(new_db, password=password)
            with contextlib.suppress(OSError):  # best effort: not every filesystem supports chmod
                os.chmod(new_db, 0o600)
            if sidecar:
                _write_private(new_sidecar, password.encode())
        except Exception as exc:
            for leftover in (new_db, new_sidecar, os.path.splitext(new_db)[0] + ".tmp"):
                with contextlib.suppress(OSError):
                    os.remove(leftover)
            logger.error(f"Failed to create KeePass DB: {exc}")
            raise MattStashError(f"Failed to create database: {exc}") from exc

        # Commit: swap in the new files; old ones were backed up above.
        os.replace(new_db, self.db_path)
        sidecar_path: Optional[str] = None
        if sidecar:
            os.replace(new_sidecar, self.sidecar_path)
            sidecar_path = self.sidecar_path
        elif os.path.exists(self.sidecar_path):
            # A stale sidecar would hold the OLD password (and mislead the resolver).
            os.remove(self.sidecar_path)

        logger.info(f"Created new KeePass DB at {self.db_path}")
        return CreatedDatabase(
            db_path=self.db_path,
            password=password,
            generated=generated,
            sidecar_path=sidecar_path,
            backups=backups,
        )
