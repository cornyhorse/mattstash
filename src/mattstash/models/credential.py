"""
mattstash.credential
--------------------
Credential data class and related utilities.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Union


@dataclass
class Credential:
    """
    Container for a KeePass entry's commonly used fields.
    The 'notes' field is used for comments/notes associated with the credential.
    """

    credential_name: str
    username: Optional[str]
    password: Optional[str]
    url: Optional[str]
    notes: Optional[str]  # Used for comments/notes
    tags: list[str]
    show_password: bool = field(default=False, repr=False)

    def __repr__(self) -> str:
        # Custom repr to mask password if show_password is False
        pwd = self.password if self.show_password else ("*****" if self.password else None)
        return (
            f"Credential(credential_name={self.credential_name!r}, username={self.username!r}, "
            f"password={pwd!r}, url={self.url!r}, notes={self.notes!r}, tags={self.tags!r})"
        )

    def as_dict(self) -> Dict[str, Any]:
        # Provide a dict representation with password masked if show_password is False
        return {
            "credential_name": self.credential_name,
            "username": self.username,
            "password": self.password if self.show_password else ("*****" if self.password else None),
            "url": self.url,
            "notes": self.notes,
            "tags": self.tags,
        }


def serialize_credential(cred: Credential, show_password: bool = False) -> Dict[str, Any]:
    """
    Return a JSON-serializable dict for a Credential, honoring show_password.

    This function does NOT mutate the original Credential object.
    """
    original_show = cred.show_password
    try:
        if show_password:
            cred.show_password = True
        return cred.as_dict()
    finally:
        cred.show_password = original_show


# Type alias for credential results
CredentialResult = Union[Credential, Dict[str, Any]]
