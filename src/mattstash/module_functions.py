"""
mattstash.module_functions
--------------------------
Module-level convenience functions for MattStash operations.
"""

from typing import Optional, Union, Dict, Any, List
from .core.mattstash import MattStash
from .models.credential import Credential

# Module-level convenience: mattstash.get("CREDENTIAL NAME")
_default_instance: Optional[MattStash] = None

CredentialResult = Union[Credential, Dict[str, Any]]


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
    global _default_instance
    if path or password or _default_instance is None:
        _default_instance = MattStash(path=path, password=password)
    return _default_instance.get_db_url(
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
    global _default_instance
    if path or password or _default_instance is None:
        _default_instance = MattStash(path=path, password=password)
    return _default_instance.get(title, show_password=show_password, version=version)


def list_creds(
        path: Optional[str] = None,
        password: Optional[str] = None,
        show_password: bool = False,
) -> List[Credential]:
    global _default_instance
    if path or password or _default_instance is None:
        _default_instance = MattStash(path=path, password=password)
    return _default_instance.list(show_password=show_password)


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
):
    """
    Create or update an entry. If only 'value' is provided, store it in the password field (credstash-like).
    Otherwise, update fields provided and return a Credential.
    Supports versioning.
    The 'notes' or 'comment' parameter can be used to set notes/comments for the credential.
    """
    global _default_instance
    if path or db_password or _default_instance is None:
        _default_instance = MattStash(path=path, password=db_password)
    # Prefer notes if provided, else comment, else None
    notes_val = notes if notes is not None else comment
    return _default_instance.put(
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
    global _default_instance
    if path or password or _default_instance is None:
        _default_instance = MattStash(path=path, password=password)
    return _default_instance.list_versions(title)


def delete(
        title: str,
        path: Optional[str] = None,
        password: Optional[str] = None,
) -> bool:
    """
    Delete an entry by title. Returns True if deleted, False otherwise.
    """
    global _default_instance
    if path or password or _default_instance is None:
        _default_instance = MattStash(path=path, password=password)
    return _default_instance.delete(title)


def get_s3_client(
        title: str,
        *,
        path: Optional[str] = None,
        password: Optional[str] = None,
        region: str = "us-east-1",
        addressing: str = "path",
        signature_version: str = "s3v4",
        retries_max_attempts: int = 10,
        verbose: bool = True,
):
    global _default_instance
    if path or password or _default_instance is None:
        _default_instance = MattStash(path=path, password=password)
    return _default_instance.get_s3_client(
        title,
        region=region,
        addressing=addressing,
        signature_version=signature_version,
        retries_max_attempts=retries_max_attempts,
        verbose=verbose,
    )
