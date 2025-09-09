"""
mattstash.exceptions
--------------------
Custom exceptions for MattStash operations.
"""


class MattStashError(Exception):
    """Base exception for all MattStash operations."""
    pass


class DatabaseNotFoundError(MattStashError):
    """Raised when the KeePass database file cannot be found."""
    pass


class DatabaseAccessError(MattStashError):
    """Raised when the database cannot be opened or accessed."""
    pass


class CredentialNotFoundError(MattStashError):
    """Raised when a requested credential entry is not found."""
    pass


class InvalidCredentialError(MattStashError):
    """Raised when credential data is invalid or incomplete."""
    pass


class VersionNotFoundError(MattStashError):
    """Raised when a specific version of a credential is not found."""
    pass


class DatabaseCorruptedError(MattStashError):
    """Raised when the database appears to be corrupted."""
    pass
