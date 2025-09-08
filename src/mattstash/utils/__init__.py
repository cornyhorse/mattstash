"""
mattstash.utils
---------------
Utility functions and classes.
"""

from .exceptions import MattStashError, DatabaseNotFoundError, DatabaseAccessError, CredentialNotFoundError

__all__ = ['MattStashError', 'DatabaseNotFoundError', 'DatabaseAccessError', 'CredentialNotFoundError']
