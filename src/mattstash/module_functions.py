"""
mattstash.module_functions
--------------------------
Module-level convenience functions for MattStash operations.

These share one lazily-created default ``MattStash`` instance. ``MattStash`` itself is
thread-safe and cross-process safe for writes, and the shared instance is swapped under a
lock, so the functions may be called from several threads. Passing ``path``/``password``
creates a fresh instance for that call (and makes it the new default); for several
databases in one process prefer explicit ``MattStash`` objects.

None of these functions creates a database: use ``MattStash.create`` or ``mattstash setup``.
Database problems raise ``DatabaseNotFoundError`` / ``DatabaseAccessError``.
"""

import threading
from typing import Any, Dict, List, Optional

from .core.mattstash import MattStash
from .models.credential import Credential

# Module-level convenience: mattstash.get("CREDENTIAL NAME")
_default_instance: Optional[MattStash] = None
_instance_lock = threading.Lock()

CredentialResult = Credential | Dict[str, Any]


def _get_instance(path: Optional[str], password: Optional[str]) -> MattStash:
    """Return the shared default instance, creating a new one if a path/password is given."""
    global _default_instance
    with _instance_lock:
        if path or password or _default_instance is None:
            _default_instance = MattStash(path=path, password=password)
        return _default_instance


def get_db_url(
    title: str,
    *,
    path: Optional[str] = None,
    password: Optional[str] = None,
    driver: Optional[str] = None,
    mask_password: bool = True,
    mask_style: str = "stars",
    database: Optional[str] = None,
    sslmode_override: Optional[str] = None,
) -> str:
    stash = _get_instance(path, password)
    return stash.get_db_url(
        title,
        driver=driver,
        mask_password=mask_password,
        mask_style=mask_style,
        database=database,
        sslmode_override=sslmode_override,
    )


def get(
    title: str,
    path: Optional[str] = None,
    password: Optional[str] = None,
    show_password: bool = False,
    version: Optional[int] = None,
) -> Optional[CredentialResult]:
    stash = _get_instance(path, password)
    return stash.get(title, show_password=show_password, version=version)


def list_creds(
    path: Optional[str] = None,
    password: Optional[str] = None,
    show_password: bool = False,
) -> List[Credential]:
    stash = _get_instance(path, password)
    return stash.list(show_password=show_password)


def put(
    title: str,
    *,
    path: Optional[str] = None,
    db_password: Optional[str] = None,
    value: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    url: Optional[str] = None,
    notes: Optional[str] = None,
    comment: Optional[str] = None,
    tags: Optional[List[str]] = None,
    version: Optional[int] = None,
    autoincrement: bool = True,
) -> Optional[CredentialResult]:
    """
    Create or update an entry. If only 'value' is provided, store it in the password field (credstash-like).
    Otherwise, update fields provided and return a Credential.
    Supports versioning.
    The 'notes' or 'comment' parameter can be used to set notes/comments for the credential.
    """
    stash = _get_instance(path, db_password)
    # Prefer notes if provided, else comment, else None
    notes_val = notes if notes is not None else comment
    return stash.put(
        title,
        value=value,
        username=username,
        password=password,
        url=url,
        notes=notes_val,
        tags=tags,
        version=version,
        autoincrement=autoincrement,
    )


def list_versions(
    title: str,
    path: Optional[str] = None,
    password: Optional[str] = None,
) -> List[str]:
    """
    List all versions (zero-padded strings) for a given title, sorted ascending.
    """
    stash = _get_instance(path, password)
    return stash.list_versions(title)


def delete(
    title: str,
    path: Optional[str] = None,
    password: Optional[str] = None,
    version: Optional[int] = None,
) -> bool:
    """
    Delete an entry by title (all of its versions, or only ``version`` if given).
    Returns True if anything was deleted, False if nothing matched.
    """
    stash = _get_instance(path, password)
    return stash.delete(title, version)


def prune(
    title: str,
    keep: int,
    path: Optional[str] = None,
    password: Optional[str] = None,
) -> List[str]:
    """Delete all but the newest ``keep`` versions of ``title``; returns the deleted versions."""
    stash = _get_instance(path, password)
    return stash.prune(title, keep)


def get_s3_client(
    title: str,
    *,
    path: Optional[str] = None,
    password: Optional[str] = None,
    region: str = "us-east-1",
    addressing: str = "path",
    signature_version: str = "s3v4",
    retries_max_attempts: int = 10,
    verbose: bool = False,
) -> Any:
    stash = _get_instance(path, password)
    return stash.get_s3_client(
        title,
        region=region,
        addressing=addressing,
        signature_version=signature_version,
        retries_max_attempts=retries_max_attempts,
        verbose=verbose,
    )
