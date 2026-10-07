"""
mattstash.core.password_resolver
--------------------------------
Handles password resolution from various sources.

Precedence (highest to lowest):
  1. ``KDBX_PASSWORD`` environment variable
  2. ``KDBX_PASSWORD_FILE`` environment variable (path to a file holding the password)
  3. Sidecar file next to the database (``.mattstash.txt``) -- kept for existing installs
An explicit password passed by the caller always wins and is handled by ``MattStash``.
"""

import errno
import os
import stat
from typing import Optional

from ..models.config import config
from ..utils.exceptions import DatabaseAccessError
from ..utils.logging_config import get_logger, security_warning

logger = get_logger(__name__)


#: A password file larger than this is a mistake (``/dev/zero``, a wrong path), not a password.
MAX_PASSWORD_FILE_BYTES = 1024 * 1024


def read_password_file(path: str) -> str:
    """Read a password from ``path`` (surrounding whitespace/newlines and a UTF-8 BOM stripped).

    Raises ``OSError`` for unreadable or oversized files and ``UnicodeDecodeError`` for non-UTF-8 content.
    """
    with open(path, "rb") as f:
        data = f.read(MAX_PASSWORD_FILE_BYTES + 1)
    if len(data) > MAX_PASSWORD_FILE_BYTES:
        raise OSError(errno.EFBIG, f"file is larger than {MAX_PASSWORD_FILE_BYTES} bytes")
    return data.decode("utf-8-sig").strip()


class PasswordResolver:
    """Handles password resolution from environment variables and the sidecar file."""

    def __init__(self, db_path: str, sidecar_basename: Optional[str] = None):
        self.db_path = db_path
        self.sidecar_basename = sidecar_basename or config.sidecar_basename

    @property
    def sidecar_path(self) -> str:
        return os.path.join(os.path.dirname(self.db_path), self.sidecar_basename)

    def resolve_password(self) -> Optional[str]:
        """Resolve the database password, or ``None`` if no source provides one."""
        password = self.resolve_from_environment()
        if password:
            return password
        return self._try_sidecar_file(self.sidecar_path)

    def resolve_from_environment(self) -> Optional[str]:
        """Resolve from ``KDBX_PASSWORD`` then ``KDBX_PASSWORD_FILE`` (never the sidecar)."""
        password = self._try_environment_variable()
        if password:
            return password
        return self._try_password_file()

    def _try_password_file(self) -> Optional[str]:
        """Read the password from the file named by ``KDBX_PASSWORD_FILE``.

        A configured-but-unreadable file is an error: silently falling back to a
        different password source would hide a deployment mistake.
        """
        path = os.getenv("KDBX_PASSWORD_FILE")
        if not path:
            return None
        try:
            pw = read_password_file(path)
        except (OSError, UnicodeDecodeError) as exc:
            raise DatabaseAccessError(f"KDBX_PASSWORD_FILE is set but cannot be read: {exc}") from exc
        logger.debug("Loaded database password from KDBX_PASSWORD_FILE")
        return pw or None

    def _try_sidecar_file(self, sidecar_path: str) -> Optional[str]:
        """Try to read password from the sidecar file."""
        if not os.path.exists(sidecar_path):
            logger.debug(f"Sidecar password file not found at {sidecar_path}")
            return None
        self._check_sidecar_permissions(sidecar_path)
        try:
            pw = read_password_file(sidecar_path)
        except (OSError, UnicodeDecodeError) as e:
            logger.warning(f"Failed to read sidecar password file: {e}")
            return None
        logger.debug("Loaded database password from sidecar file")
        return pw or None

    def _try_environment_variable(self) -> Optional[str]:
        """Try to read password from the ``KDBX_PASSWORD`` environment variable."""
        env_pw = os.getenv("KDBX_PASSWORD")
        if env_pw:
            logger.debug("Loaded database password from KDBX_PASSWORD")
            return env_pw
        logger.debug("Environment variable KDBX_PASSWORD not set")
        return None

    @staticmethod
    def _check_sidecar_permissions(sidecar_path: str) -> None:
        """Warn if the sidecar is readable/writable by group or others."""
        try:
            mode = os.stat(sidecar_path).st_mode
        except OSError:  # pragma: no cover
            return
        if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
            security_warning(
                f"Sidecar password file has insecure permissions: {oct(stat.S_IMODE(mode))}. "
                f"Should be 0600 (owner read/write only). File: {sidecar_path}"
            )
