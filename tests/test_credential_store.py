"""
Test the credential store module functionality.
"""

import os
import pytest
from pathlib import Path
from unittest.mock import Mock, patch

from mattstash.credential_store import CredentialStore
from mattstash.exceptions import DatabaseNotFoundError, DatabaseAccessError


def test_credential_store_initialization():
    """Test basic credential store initialization"""
    store = CredentialStore("/path/to/db.kdbx", "password")
    assert store.db_path == "/path/to/db.kdbx"
    assert store.password == "password"
    assert store._kp is None


def test_open_nonexistent_database():
    """Test opening a database that doesn't exist"""
    store = CredentialStore("/nonexistent/path.kdbx", "password")

    with pytest.raises(DatabaseNotFoundError):
        store.open()


def test_open_no_password():
    """Test opening database without password"""
    # Create a temporary file to simulate database existence
    with patch('os.path.exists', return_value=True):
        store = CredentialStore("/path/to/db.kdbx", "")

        with pytest.raises(DatabaseAccessError):
            store.open()


def test_open_invalid_password(temp_db: Path):
    """Test opening database with wrong password"""
    # First create a valid database
    from mattstash.core import MattStash
    ms = MattStash(path=str(temp_db))
    ms._ensure_open()  # This creates and opens the database

    # Now try with wrong password
    store = CredentialStore(str(temp_db), "wrong_password")

    with pytest.raises(DatabaseAccessError):
        store.open()


def test_successful_database_operations(temp_db: Path):
    """Test successful database operations"""
    # Create database first
    from mattstash.core import MattStash
    ms = MattStash(path=str(temp_db))
    password = ms.password

    # Test credential store operations
    store = CredentialStore(str(temp_db), password)
    kp = store.open()
    assert kp is not None

    # Test creating entry
    entry = store.create_entry("test_title", "test_user", "test_pass", "test_url", "test_notes")
    assert entry.title == "test_title"
    assert entry.username == "test_user"

    # Test saving
    store.save()

    # Test finding entry
    found = store.find_entry_by_title("test_title")
    assert found is not None
    assert found.title == "test_title"

    # Test finding entries by prefix
    entries = store.find_entries_by_prefix("test")
    assert len(entries) >= 1
    assert any(e.title == "test_title" for e in entries)

    # Test getting all entries
    all_entries = store.get_all_entries()
    assert len(all_entries) >= 1

    # Test deleting entry
    result = store.delete_entry(entry)
    assert result is True


def test_delete_entry_failure(temp_db: Path):
    """Test delete entry with mock failure"""
    from mattstash.core import MattStash
    ms = MattStash(path=str(temp_db))
    password = ms.password

    store = CredentialStore(str(temp_db), password)

    # Create a mock entry
    mock_entry = Mock()

    # Mock the delete operation to fail
    with patch.object(store, 'open') as mock_open:
        mock_kp = Mock()
        mock_kp.delete_entry.side_effect = Exception("Delete failed")
        mock_open.return_value = mock_kp

        result = store.delete_entry(mock_entry)
        assert result is False


def test_find_entries_by_prefix_empty_result(temp_db: Path):
    """Test finding entries by prefix with no matches"""
    from mattstash.core import MattStash
    ms = MattStash(path=str(temp_db))
    password = ms.password

    store = CredentialStore(str(temp_db), password)
    store.open()

    entries = store.find_entries_by_prefix("nonexistent")
    assert entries == []


def test_find_entry_by_title_not_found(temp_db: Path):
    """Test finding entry by title when it doesn't exist"""
    from mattstash.core import MattStash
    ms = MattStash(path=str(temp_db))
    password = ms.password

    store = CredentialStore(str(temp_db), password)
    store.open()

    entry = store.find_entry_by_title("nonexistent")
    assert entry is None


@pytest.fixture()
def temp_db(tmp_path: Path) -> Path:
    """Create an isolated directory for each test to hold DB + sidecar."""
    d = tmp_path / "mattstash"
    d.mkdir()
    return d / "test.kdbx"
