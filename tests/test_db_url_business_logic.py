"""
Unit tests for specific db_url.py business logic paths to achieve 100% coverage.
"""

import pytest
from unittest.mock import Mock, patch

from mattstash.builders.db_url import DatabaseUrlBuilder


def test_db_url_builder_mask_style_omit():
    """Test password masking with 'omit' style - covers line 123"""
    mock_mattstash = Mock()
    builder = DatabaseUrlBuilder(mock_mattstash)

    # Mock credential with password
    mock_cred = Mock()
    mock_cred.username = "testuser"
    mock_cred.password = "testpass"
    mock_cred.url = "localhost:5432"

    # Mock the database entry with custom properties
    mock_entry = Mock()
    mock_entry.get_custom_property.side_effect = lambda key: {
        "database": "testdb",
        "sslmode": None
    }.get(key)

    mock_mattstash.get.return_value = mock_cred
    mock_mattstash._ensure_initialized.return_value = True
    mock_mattstash._credential_store.open.return_value.find_entries.return_value = mock_entry

    # Test mask_style="omit" - should omit password entirely
    result = builder.build_url("test", mask_password=True, mask_style="omit")

    # Should contain only username, no password section
    assert "testuser@localhost:5432" in result
    assert ":*****" not in result
    assert ":testpass" not in result


def test_db_url_builder_unmasked_no_password():
    """Test unmasked mode when no password exists - covers line 128"""
    mock_mattstash = Mock()
    builder = DatabaseUrlBuilder(mock_mattstash)

    # Mock credential without password
    mock_cred = Mock()
    mock_cred.username = "testuser"
    mock_cred.password = None  # No password
    mock_cred.url = "localhost:5432"

    # Mock the database entry with custom properties
    mock_entry = Mock()
    mock_entry.get_custom_property.side_effect = lambda key: {
        "database": "testdb",
        "sslmode": None
    }.get(key)

    mock_mattstash.get.return_value = mock_cred
    mock_mattstash._ensure_initialized.return_value = True
    mock_mattstash._credential_store.open.return_value.find_entries.return_value = mock_entry

    # Test mask_password=False with no password
    result = builder.build_url("test", mask_password=False)

    # Should contain only username, no password section
    assert "testuser@localhost:5432" in result
    assert ":" not in result.split("@")[0].split("//")[1]  # No colon after username


def test_db_url_builder_with_sslmode():
    """Test SSL mode parameter addition - covers line 134"""
    mock_mattstash = Mock()
    builder = DatabaseUrlBuilder(mock_mattstash)

    # Mock credential
    mock_cred = Mock()
    mock_cred.username = "testuser"
    mock_cred.password = "testpass"
    mock_cred.url = "localhost:5432"

    # Mock the database entry with SSL mode
    mock_entry = Mock()
    mock_entry.get_custom_property.side_effect = lambda key: {
        "database": "testdb",
        "sslmode": "require"  # SSL mode present
    }.get(key)

    mock_mattstash.get.return_value = mock_cred
    mock_mattstash._ensure_initialized.return_value = True
    mock_mattstash._credential_store.open.return_value.find_entries.return_value = mock_entry

    # Test with SSL mode
    result = builder.build_url("test")

    # Should include SSL mode as query parameter
    assert "?sslmode=require" in result
    assert result.endswith("testdb?sslmode=require")


def test_db_url_builder_sslmode_override():
    """Test SSL mode override parameter"""
    mock_mattstash = Mock()
    builder = DatabaseUrlBuilder(mock_mattstash)

    # Mock credential
    mock_cred = Mock()
    mock_cred.username = "testuser"
    mock_cred.password = "testpass"
    mock_cred.url = "localhost:5432"

    # Mock the database entry with different SSL mode
    mock_entry = Mock()
    mock_entry.get_custom_property.side_effect = lambda key: {
        "database": "testdb",
        "sslmode": "prefer"  # Will be overridden
    }.get(key)

    mock_mattstash.get.return_value = mock_cred
    mock_mattstash._ensure_initialized.return_value = True
    mock_mattstash._credential_store.open.return_value.find_entries.return_value = mock_entry

    # Test with SSL mode override
    result = builder.build_url("test", sslmode_override="disable")

    # Should use override value, not the entry's sslmode
    assert "?sslmode=disable" in result
    assert "sslmode=prefer" not in result


def test_db_url_builder_masked_stars_no_password():
    """Test masked stars style when no password exists"""
    mock_mattstash = Mock()
    builder = DatabaseUrlBuilder(mock_mattstash)

    # Mock credential without password
    mock_cred = Mock()
    mock_cred.username = "testuser"
    mock_cred.password = ""  # Empty password
    mock_cred.url = "localhost:5432"

    # Mock the database entry
    mock_entry = Mock()
    mock_entry.get_custom_property.side_effect = lambda key: {
        "database": "testdb",
        "sslmode": None
    }.get(key)

    mock_mattstash.get.return_value = mock_cred
    mock_mattstash._ensure_initialized.return_value = True
    mock_mattstash._credential_store.open.return_value.find_entries.return_value = mock_entry

    # Test mask_style="stars" with no password
    result = builder.build_url("test", mask_password=True, mask_style="stars")

    # Should contain only username, no stars when no password
    assert "testuser@localhost:5432" in result
    assert ":*****" not in result


def test_db_url_builder_unmasked_with_password():
    """Test unmasked mode with password present"""
    mock_mattstash = Mock()
    builder = DatabaseUrlBuilder(mock_mattstash)

    # Mock credential with password
    mock_cred = Mock()
    mock_cred.username = "testuser"
    mock_cred.password = "secretpass"
    mock_cred.url = "localhost:5432"

    # Mock the database entry
    mock_entry = Mock()
    mock_entry.get_custom_property.side_effect = lambda key: {
        "database": "testdb",
        "sslmode": None
    }.get(key)

    mock_mattstash.get.return_value = mock_cred
    mock_mattstash._ensure_initialized.return_value = True
    mock_mattstash._credential_store.open.return_value.find_entries.return_value = mock_entry

    # Test mask_password=False with password
    result = builder.build_url("test", mask_password=False)

    # Should contain actual password
    assert "testuser:secretpass@localhost:5432" in result


def test_db_url_builder_credential_not_found():
    """Test error when credential entry is not found - covers line 109"""
    mock_mattstash = Mock()
    builder = DatabaseUrlBuilder(mock_mattstash)

    # Mock credential exists but entry lookup fails
    mock_cred = Mock()
    mock_cred.username = "testuser"
    mock_cred.password = "testpass"
    mock_cred.url = "localhost:5432"

    mock_mattstash.get.return_value = mock_cred
    mock_mattstash._ensure_initialized.return_value = True

    # Mock database operations - no entry found and no versioned entries
    mock_kp = Mock()
    mock_kp.find_entries.return_value = None  # Entry not found
    mock_kp.entries = []  # No versioned entries either
    mock_mattstash._credential_store.open.return_value = mock_kp

    # Should raise ValueError when entry is not found
    with pytest.raises(ValueError, match="Credential entry not found: nonexistent"):
        builder.build_url("nonexistent")


def test_db_url_builder_versioned_entry_resolution():
    """Test successful versioned entry resolution - covers the max() line"""
    mock_mattstash = Mock()
    builder = DatabaseUrlBuilder(mock_mattstash)

    # Mock credential
    mock_cred = Mock()
    mock_cred.username = "testuser"
    mock_cred.password = "testpass"
    mock_cred.url = "localhost:5432"

    mock_mattstash.get.return_value = mock_cred
    mock_mattstash._ensure_initialized.return_value = True

    # Mock database operations - no direct entry but versioned entries exist
    mock_kp = Mock()
    mock_kp.find_entries.return_value = None  # Direct entry not found

    # Create mock versioned entries
    mock_entry_v1 = Mock()
    mock_entry_v1.title = "test@0000000001"
    mock_entry_v2 = Mock()
    mock_entry_v2.title = "test@0000000003"  # Higher version
    mock_entry_v2.get_custom_property.side_effect = lambda key: {
        "database": "testdb",
        "sslmode": None
    }.get(key)

    # Mock other entries that shouldn't match
    mock_other_entry = Mock()
    mock_other_entry.title = "other@0000000001"

    mock_kp.entries = [mock_entry_v1, mock_other_entry, mock_entry_v2]
    mock_mattstash._credential_store.open.return_value = mock_kp

    # Should successfully find the highest versioned entry (v3)
    result = builder.build_url("test")

    # Should successfully build URL using the highest version entry
    assert "postgresql://testuser:*****@localhost:5432/testdb" in result

