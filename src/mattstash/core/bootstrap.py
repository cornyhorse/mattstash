"""
mattstash.core.bootstrap
------------------------
Database bootstrap and initialization functionality.
"""

import os
import sys
import secrets
from typing import Optional

from ..models.config import config

try:
    from pykeepass import create_database as _kp_create_database  # type: ignore
except Exception:  # pragma: no cover
    _kp_create_database = None


class DatabaseBootstrapper:
    """Handles database initialization and bootstrap operations."""

    def __init__(self, db_path: str, sidecar_basename: str = None):
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
                return  # Only bootstrap when BOTH are absent

            self._create_database_and_sidecar(db_dir, sidecar)

        except Exception as e:
            # Non-fatal: we fall back to the normal resolve/open path
            print(f"[MattStash] Bootstrap skipped due to error: {e}", file=sys.stderr)

    def _create_database_and_sidecar(self, db_dir: str, sidecar_path: str) -> None:
        """Create the database directory, sidecar file, and empty database."""
        # Ensure directory exists with restrictive perms
        os.makedirs(db_dir, exist_ok=True)
        try:
            os.chmod(db_dir, 0o700)
        except Exception:
            # Best-effort on non-POSIX or restricted environments
            pass

        # Generate a strong password for the DB and write the sidecar (0600)
        pw = secrets.token_urlsafe(32)

        with open(sidecar_path, "wb") as f:
            f.write(pw.encode())
        try:
            os.chmod(sidecar_path, 0o600)
        except Exception:
            pass

        # Create an empty KeePass database
        try:
            if _kp_create_database is None:
                raise RuntimeError("pykeepass.create_database not available in this version")
            _kp_create_database(self.db_path, password=pw)
            print(f"[MattStash] Created new KeePass DB at {self.db_path} and sidecar {sidecar_path}", file=sys.stderr)
        except Exception as e:
            print(f"[MattStash] Failed to create KeePass DB at {self.db_path}: {e}", file=sys.stderr)
