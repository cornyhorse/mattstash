"""
MattStash: KeePass-backed secrets management
============================================

A simple, credstash-like interface to KeePass databases.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

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

try:
    __version__: str = _pkg_version("mattstash")
except PackageNotFoundError:
    __version__ = "0.0.0"  # fallback for editable / uninstalled

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
