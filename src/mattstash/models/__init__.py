"""
mattstash.models
----------------
Data models and configuration classes.
"""

from .credential import Credential, CredentialResult
from .config import config

__all__ = ['Credential', 'CredentialResult', 'config']
