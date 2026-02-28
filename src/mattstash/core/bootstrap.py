"""
mattstash.core.bootstrap
------------------------
Database bootstrap and initialization functionality.
"""

import os
import secrets
import stat
from typing import Optional

from ..models.config import config
from ..utils.logging_config import get_logger, security_warning

logger = get_logger(__name__)

try:
    from pykeepass import create_database as _kp_create_database
except Exception:  # pragma: no cover
    _kp_create_database = None


class DatabaseBootstrapper:
    """Handles database initialization and bootstrap operations."""

    def __init__(self, db_path: str, sidecar_basename: Optional[str] = None):
        self.db_path = db_path
        self.sidecar_basename = sidecar_basename or config.sidecar_basename

    def bootstrap_if_missing(self) -> None:
        """
        If BOTH the KeePass DB and the sidecar password file are missing, create them.
        This mirrors a credstash-like 'setup' step: we generate a strong password,
        write it to the sidecar, and initialize an empty KeePass database.
        """
        try:
            db_dir = os.path.dirname(self.db_path) or "."
            sidecar = os.path.join(db_dir, self.sidecar_basename)
            db_exists = os.path.exists(self.db_path)
            sidecar_exists = os.path.exists(sidecar)

            if db_exists or sidecar_exists:
                # Check sidecar permissions if it exists
                if sidecar_exists:
                    self._check_sidecar_permissions(sidecar)
                return  # Only bootstrap when BOTH are absent

            self._create_database_and_sidecar(db_dir, sidecar)

        except Exception as e:
            # Non-fatal: we fall back to the normal resolve/open path
            logger.warning(f"Bootstrap skipped due to error: {e}")

    def _check_sidecar_permissions(self, sidecar_path: str) -> None:
        """Check and warn if sidecar file has overly permissive permissions."""
        try:
            file_stat = os.stat(sidecar_path)
            mode = file_stat.st_mode

            # Check if file is readable/writable by group or others
            if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
                security_warning(
                    f"Sidecar password file has insecure permissions: {oct(stat.S_IMODE(mode))}. "
                    f"Should be 0600 (owner read/write only). File: {sidecar_path}"
                )
        except Exception:  # pragma: no cover
            # Couldn't check permissions - might be non-POSIX system
            pass  # pragma: no cover

    def _create_database_and_sidecar(self, db_dir: str, sidecar_path: str) -> None:
        """Create the database directory, sidecar file, and empty database."""
        # Ensure directory exists with restrictive perms
        os.makedirs(db_dir, exist_ok=True)
        try:
            os.chmod(db_dir, 0o700)
        except Exception:  # pragma: no cover
            # Best-effort on non-POSIX or restricted environments  # pragma: no cover
            pass  # pragma: no cover

        # Generate a strong password for the DB and write the sidecar (0600)
        pw = secrets.token_urlsafe(32)

        with open(sidecar_path, "wb") as f:
            f.write(pw.encode())
        try:
            os.chmod(sidecar_path, 0o600)
            # Verify permissions were set correctly
            self._check_sidecar_permissions(sidecar_path)
        except Exception:
            pass

        # Create an empty KeePass database
        try:
            if _kp_create_database is None:
                raise RuntimeError("pykeepass.create_database not available in this version")
            _kp_create_database(self.db_path, password=pw)
            logger.info(f"Created new KeePass DB at {self.db_path} and sidecar {sidecar_path}")
        except Exception as e:
            logger.error(f"Failed to create KeePass DB: {e}")
