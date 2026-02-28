"""
mattstash.models
----------------
Data models and configuration classes.
"""

from .config import config
from .credential import Credential, CredentialResult

__all__ = ["Credential", "CredentialResult", "config"]
