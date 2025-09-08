"""
mattstash.core.password_resolver
--------------------------------
Handles password resolution from various sources.
"""

import os
import sys
from typing import Optional

from ..models.config import config


class PasswordResolver:
    """Handles password resolution from sidecar files and environment variables."""

    def __init__(self, db_path: str, sidecar_basename: str = None):
        self.db_path = db_path
        self.sidecar_basename = sidecar_basename or config.sidecar_basename

    def resolve_password(self) -> Optional[str]:
        """
        Resolve password from various sources in order of priority:
        1. Sidecar plaintext file next to the DB
        2. KDBX_PASSWORD environment variable
        """
        # 1) Sidecar plaintext file next to the DB
        sidecar_path = os.path.join(os.path.dirname(self.db_path), self.sidecar_basename)
        password = self._try_sidecar_file(sidecar_path)
        if password:
            return password

        # 2) Environment variable
        return self._try_environment_variable()

    def _try_sidecar_file(self, sidecar_path: str) -> Optional[str]:
        """Try to read password from sidecar file."""
        try:
            if os.path.exists(sidecar_path):
                try:
                    with open(sidecar_path, "rb") as f:
                        pw = f.read().decode().strip()
                        print(f"[MattStash] Loaded password from sidecar file {sidecar_path}", file=sys.stderr)
                        return pw
                except Exception:
                    print(f"[MattStash] Failed to read sidecar password file {sidecar_path}", file=sys.stderr)
            else:
                print(f"[MattStash] Sidecar password file not found at {sidecar_path}", file=sys.stderr)
        except Exception:
            # Shouldn't really happen, but just in case
            pass
        return None

    def _try_environment_variable(self) -> Optional[str]:
        """Try to read password from environment variable."""
        env_pw = os.getenv("KDBX_PASSWORD")
        if env_pw is not None:
            print("[MattStash] Loaded password from environment variable KDBX_PASSWORD", file=sys.stderr)
        else:
            print("[MattStash] Environment variable KDBX_PASSWORD not set", file=sys.stderr)
        return env_pw
