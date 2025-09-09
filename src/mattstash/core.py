"""
mattstash.core
--------------
Core MattStash class for KeePass-backed secrets management.
"""

from __future__ import annotations  # pragma: no cover

# Import from the new refactored structure  # pragma: no cover
from .core.mattstash import MattStash  # pragma: no cover
from .models.config import config  # pragma: no cover
from .models.credential import Credential, CredentialResult  # pragma: no cover

# For backward compatibility, re-export the main class and constants  # pragma: no cover
DEFAULT_KDBX_PATH = config.default_db_path  # pragma: no cover
DEFAULT_KDBX_SIDECAR_BASENAME = config.sidecar_basename  # pragma: no cover
PAD_WIDTH = config.version_pad_width  # pragma: no cover

# Re-export the main class for backward compatibility  # pragma: no cover
__all__ = ['MattStash', 'Credential', 'CredentialResult', 'DEFAULT_KDBX_PATH', 'DEFAULT_KDBX_SIDECAR_BASENAME', 'PAD_WIDTH']  # pragma: no cover
