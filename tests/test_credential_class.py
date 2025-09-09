"""
Test coverage for Credential class and core functionality.
"""

import pytest
from mattstash import Credential, MattStash


def test_credential_repr_with_password_shown():
    """Test Credential __repr__ with show_password=True"""
    cred = Credential(
        credential_name="test",
        username="user",
        password="secret",
        url="https://example.com",
        notes="test notes",
        tags=["tag1", "tag2"],
        show_password=True
    )

    repr_str = repr(cred)
    assert "test" in repr_str
    assert "user" in repr_str
    assert "secret" in repr_str  # Password should be visible
    assert "https://example.com" in repr_str
    assert "test notes" in repr_str
    assert "tag1" in repr_str


def test_credential_repr_with_password_hidden():
    """Test Credential __repr__ with show_password=False (default)"""
    cred = Credential(
        credential_name="test",
        username="user",
        password="secret",
        url="https://example.com",
        notes="test notes",
        tags=["tag1", "tag2"]
    )

    repr_str = repr(cred)
    assert "test" in repr_str
    assert "user" in repr_str
    assert "secret" not in repr_str  # Password should be masked
    assert "*****" in repr_str  # Should show mask


def test_credential_repr_with_no_password():
    """Test Credential __repr__ with None password"""
    cred = Credential(
        credential_name="test",
        username="user",
        password=None,
        url="https://example.com",
        notes="test notes",
        tags=["tag1", "tag2"]
    )

    repr_str = repr(cred)
    assert "None" in repr_str  # Should show None for empty password


def test_credential_as_dict_with_password_shown():
    """Test Credential as_dict with show_password=True"""
    cred = Credential(
        credential_name="test",
        username="user",
        password="secret",
        url="https://example.com",
        notes="test notes",
        tags=["tag1", "tag2"],
        show_password=True
    )

    result = cred.as_dict()
    assert result["credential_name"] == "test"
    assert result["username"] == "user"
    assert result["password"] == "secret"  # Should show real password
    assert result["url"] == "https://example.com"
    assert result["notes"] == "test notes"
    assert result["tags"] == ["tag1", "tag2"]


def test_credential_as_dict_with_password_hidden():
    """Test Credential as_dict with show_password=False"""
    cred = Credential(
        credential_name="test",
        username="user",
        password="secret",
        url="https://example.com",
        notes="test notes",
        tags=["tag1", "tag2"],
        show_password=False
    )

    result = cred.as_dict()
    assert result["credential_name"] == "test"
    assert result["username"] == "user"
    assert result["password"] == "*****"  # Should be masked
    assert result["url"] == "https://example.com"
    assert result["notes"] == "test notes"
    assert result["tags"] == ["tag1", "tag2"]


def test_credential_as_dict_with_no_password():
    """Test Credential as_dict with None password"""
    cred = Credential(
        credential_name="test",
        username="user",
        password=None,
        url="https://example.com",
        notes="test notes",
        tags=["tag1", "tag2"]
    )

    result = cred.as_dict()
    assert result["password"] is None
