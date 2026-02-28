"""
MattStash: KeePass-backed secrets management
============================================

A simple, credstash-like interface to KeePass databases.
"""

# Import from the new refactored structure
# Import CLI entry point
from .cli.main import main as cli_main
from .core.mattstash import MattStash
from .models.config import config
from .models.credential import Credential, CredentialResult, serialize_credential

# Import module-level functions for backward compatibility
from .module_functions import (
    delete,
    get,
    get_db_url,
    get_s3_client,
    list_creds,
    list_versions,
    put,
)

# Re-export configuration constants for backward compatibility
DEFAULT_KDBX_PATH = config.default_db_path
DEFAULT_KDBX_SIDECAR_BASENAME = config.sidecar_basename
PAD_WIDTH = config.version_pad_width

__version__ = "0.1.2"

__all__ = [
    # Constants
    "DEFAULT_KDBX_PATH",
    "DEFAULT_KDBX_SIDECAR_BASENAME",
    "PAD_WIDTH",
    "Credential",
    "CredentialResult",
    # Main classes
    "MattStash",
    # CLI
    "cli_main",
    # Configuration
    "config",
    "delete",
    # Module functions
    "get",
    "get_db_url",
    "get_s3_client",
    "list_creds",
    "list_versions",
    "put",
    # Utility functions
    "serialize_credential",
]
