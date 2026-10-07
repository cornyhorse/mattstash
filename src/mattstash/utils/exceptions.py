"""
mattstash.exceptions
--------------------
Custom exceptions for MattStash operations.
"""

from typing import Optional


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


class DatabaseExistsError(MattStashError):
    """Raised when creating a database would overwrite existing files."""

    pass


class DatabaseLockError(MattStashError):
    """Raised when the cross-process database lock cannot be acquired in time."""

    pass


class SidecarUpdateError(MattStashError):
    """The database was re-keyed but the sidecar password file next to it could not be updated.

    The database already uses the new password; the sidecar still holds the old one.
    """

    pass


class ServerError(MattStashError):
    """Raised by the CLI's HTTP client when a MattStash server request fails.

    The message never contains the API key or any part of the response body.
    """

    def __init__(self, message: str, status_code: Optional[int] = None, *, secret_missing: bool = False) -> None:
        super().__init__(message)
        self.status_code = status_code
        #: True only for a 404 that the MattStash server itself answered with "Credential not found": a wrong URL,
        #: a proxy's 404 page or a name the server cannot route is a *different* problem.
        self.secret_missing = secret_missing
