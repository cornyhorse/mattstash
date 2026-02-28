"""
mattstash.core
--------------
Core MattStash class for KeePass-backed secrets management.

This module provides backward compatibility re-exports of the refactored structure.
"""

from __future__ import annotations

# Import from the new refactored structure
from .core.mattstash import MattStash
from .models.config import config
from .models.credential import Credential, CredentialResult

# For backward compatibility, re-export the main class and constants
DEFAULT_KDBX_PATH = config.default_db_path
DEFAULT_KDBX_SIDECAR_BASENAME = config.sidecar_basename
PAD_WIDTH = config.version_pad_width

# Re-export the main class for backward compatibility
__all__ = [
    "DEFAULT_KDBX_PATH",
    "DEFAULT_KDBX_SIDECAR_BASENAME",
    "PAD_WIDTH",
    "Credential",
    "CredentialResult",
    "MattStash",
]
