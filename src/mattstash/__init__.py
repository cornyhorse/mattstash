"""
MattStash: KeePass-backed secrets management
============================================

A simple, credstash-like interface to KeePass databases.
"""

# Import from the new refactored structure
from .core.mattstash import MattStash
from .models.credential import Credential, CredentialResult, serialize_credential
from .models.config import config

# Import CLI entry point
from .cli.main import main as cli_main

# Import module-level functions for backward compatibility
from .module_functions import (
    get,
    put,
    delete,
    list_creds,
    list_versions,
    get_db_url,
    get_s3_client,
)

# Re-export configuration constants for backward compatibility
DEFAULT_KDBX_PATH = config.default_db_path
DEFAULT_KDBX_SIDECAR_BASENAME = config.sidecar_basename
PAD_WIDTH = config.version_pad_width

__version__ = "0.1.2"

__all__ = [
    # Main classes
    "MattStash",
    "Credential",
    "CredentialResult",
    # Module functions
    "get",
    "put",
    "delete",
    "list_creds",
    "list_versions",
    "get_db_url",
    "get_s3_client",
    # Utility functions
    "serialize_credential",
    # CLI
    "cli_main",
    # Constants
    "DEFAULT_KDBX_PATH",
    "DEFAULT_KDBX_SIDECAR_BASENAME",
    "PAD_WIDTH",
    # Configuration
    "config",
]
